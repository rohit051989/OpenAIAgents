"""
Path Utilities for Information Graph
=====================================
Converts between the repo-relative paths stored in Neo4j and the
absolute local paths needed for file-system access.

Relative path format:  {repo_name}/{forward/slash/relative/path}
  e.g.  Test_Code_repo/batch/TestSpringProject/src/main/java/com/foo/Bar.java

For nodes outside any known repo (the scan root itself):
           __root__/{forward/slash/relative/path}
"""

import os
from pathlib import Path
from typing import Dict, List, Optional


def to_relative_path(abs_path: Path, repos_config: List[Dict],
                     root_directory: str) -> str:
    """Convert an absolute filesystem path to a repo-relative graph path.

    Args:
        abs_path:        Absolute path to convert.
        repos_config:    List of repository dicts from information_graph_config.yaml.
        root_directory:  The root_directory value from the config.

    Returns:
        Relative path string such as ``Test_Code_repo/src/main/java/Foo.java``.
        Falls back to the normalised absolute path if no match is found.
    """
    abs_str = str(abs_path.absolute()).replace('\\', '/')

    for repo_cfg in repos_config:
        repo_local = str(Path(repo_cfg['path']).absolute()).replace('\\', '/')
        repo_name = repo_cfg['name']
        if abs_str == repo_local:
            return repo_name                       # The repo root itself
        if abs_str.startswith(repo_local + '/'):
            relative = abs_str[len(repo_local) + 1:]
            return f"{repo_name}/{relative}"

    root_abs = str(Path(root_directory).absolute()).replace('\\', '/')
    if abs_str == root_abs:
        return '__root__'
    if abs_str.startswith(root_abs + '/'):
        relative = abs_str[len(root_abs) + 1:]
        return f"__root__/{relative}"

    # Fallback – return normalised absolute path unchanged
    return abs_str


def to_absolute_path(relative_path: str, repos_config: List[Dict],
                     root_directory: str) -> str:
    """Convert a repo-relative graph path back to an absolute local filesystem path.

    Args:
        relative_path:   Relative path stored in the graph.
        repos_config:    List of repository dicts from information_graph_config.yaml.
        root_directory:  The root_directory value from the config.

    Returns:
        Absolute path string suitable for filesystem access.
        Returns the input unchanged if it cannot be resolved.
    """
    if not relative_path:
        return ""

    rel = relative_path.replace('\\', '/')
    parts = rel.split('/', 1)
    prefix = parts[0]

    if prefix == '__root__':
        if len(parts) == 1:
            return str(Path(root_directory))
        return str(Path(root_directory) / parts[1].replace('/', os.sep))

    for repo_cfg in repos_config:
        if repo_cfg['name'] == prefix:
            if len(parts) == 1:
                return str(Path(repo_cfg['path']))
            return str(Path(repo_cfg['path']) / parts[1].replace('/', os.sep))

    # Fallback – treat as absolute path already (may be un-migrated old data)
    return relative_path.replace('/', os.sep)


# ---------------------------------------------------------------------------
# Java method source extraction — overload-aware shared utility
# ---------------------------------------------------------------------------

import re as _re
from typing import List as _List, Optional as _Optional, Tuple as _Tuple


def param_types_from_method_fqn(method_fqn: str) -> _List[str]:
    """Parse the parameter type list stored inside a MethodDef FQN.

    The FQN format produced by ``MethodDef.method_key`` is::

        com.example.Foo.doStuff(String,int)

    Returns a list of simple type strings, e.g. ``['String', 'int']``.
    Returns an empty list when the FQN has no parentheses (pre-overload data).
    """
    paren = method_fqn.rfind('(')
    if paren == -1:
        return []
    params_str = method_fqn[paren + 1:].rstrip(')')
    if not params_str.strip():
        return []
    return [t.strip() for t in params_str.split(',') if t.strip()]


def extract_java_method_source(file_content: str,
                                method_name: str,
                                param_types: _Optional[_List[str]] = None,
                                max_lines: _Optional[int] = None) -> str:
    """Extract the source of a Java method, with overload disambiguation.

    Finds **all** declarations of *method_name* in *file_content*, then
    returns the one whose parameter types best match *param_types*.

    Matching priority (when multiple overloads exist):
    1. Arity (parameter count) must match — hard filter.
    2. Simple type-name equality for non-None entries in *param_types*.
    3. First declaration when still ambiguous or *param_types* is None/empty.

    Args:
        file_content: Full Java source as a string.
        method_name:  Unqualified Java method name.
        param_types:  List of expected parameter types (simple or FQ names).
                      ``None`` / empty list → return first match.
        max_lines:    If set, cap the returned source at this many lines (with
                      a truncation marker appended).

    Returns:
        Method source as a string, or ``""`` if not found.
    """
    # Pattern: mandatory access modifier + optional extra modifiers + return
    # type (non-greedy) + method name + opening '('.
    decl_re = _re.compile(
        rf'(?:(?:public|private|protected)\s+)'
        rf'(?:(?:static|final|synchronized|abstract|native|default|strictfp)\s+)*'
        rf'(?:(?:[\w<>\[\].,\s]+?)\s+)'   # return type (non-greedy)
        rf'{_re.escape(method_name)}\s*\(',
        _re.DOTALL,
    )

    candidates: _List[_Tuple[str, str]] = []  # (param_text, full_source)

    for m in decl_re.finditer(file_content):
        # The last character of the match is '(' — the opening paren.
        paren_start = m.end() - 1

        # Walk forward to find the matching ')' respecting <> nesting.
        angle_depth = paren_depth = 0
        param_end = -1
        for i in range(paren_start, len(file_content)):
            c = file_content[i]
            if c == '<':
                angle_depth += 1
            elif c == '>' and angle_depth > 0:
                angle_depth -= 1
            elif c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    param_end = i
                    break

        if param_end == -1:
            continue

        # Verify that '{' follows immediately after optional 'throws' clause.
        after_close = file_content[param_end + 1: param_end + 300]
        throws_brace = _re.match(
            r'[\s\n]*(?:throws\s+[\w,\s<>.]+?)?\s*\{',
            after_close, _re.DOTALL,
        )
        if not throws_brace:
            continue

        # Absolute index of the opening '{'.
        brace_abs = param_end + 1 + throws_brace.end() - 1

        # Walk the body to find the matching '}'.
        brace_count = 1
        pos = brace_abs + 1
        while pos < len(file_content) and brace_count > 0:
            c = file_content[pos]
            if c == '{':
                brace_count += 1
            elif c == '}':
                brace_count -= 1
            pos += 1

        if brace_count != 0:
            continue

        param_text = file_content[paren_start + 1: param_end].strip()
        full_source = file_content[m.start(): pos]
        candidates.append((param_text, full_source))

    if not candidates:
        return ""

    # ---- Overload disambiguation ----------------------------------------

    def _split_params(param_text: str) -> _List[str]:
        """Split on commas respecting <> nesting; return raw decl strings."""
        if not param_text.strip():
            return []
        result, depth, buf = [], 0, []
        for c in param_text:
            if c == '<':
                depth += 1
                buf.append(c)
            elif c == '>':
                depth -= 1
                buf.append(c)
            elif c == ',' and depth == 0:
                result.append(''.join(buf).strip())
                buf = []
            else:
                buf.append(c)
        if buf:
            result.append(''.join(buf).strip())
        return result

    def _decl_to_type(decl: str) -> str:
        """'SomeType name' or 'SomeType... name'  →  'SomeType'."""
        decl = decl.replace('...', '').strip()
        decl = _re.sub(r'@\w+\s*', '', decl).strip()  # strip annotations
        parts = decl.rsplit(None, 1)
        return parts[0].strip() if len(parts) > 1 else decl

    def _simple(t: str) -> str:
        """Strip package prefix and generics for loose comparison."""
        return t.split('.')[-1].split('<')[0].strip() if t else ''

    def _score(param_text: str, wanted: _List[str]) -> int:
        decls = _split_params(param_text)
        if len(decls) != len(wanted):
            return -1           # arity mismatch — hard exclude
        s = 10                  # base points for arity match
        for d, w in zip(decls, wanted):
            if w and _simple(_decl_to_type(d)) == _simple(w):
                s += 1
        return s

    if len(candidates) == 1 or not param_types:
        best_source = candidates[0][1]
    else:
        scored = [(_score(pt, param_types), src) for pt, src in candidates]
        best_score = max(s for s, _ in scored)
        if best_score < 0:
            best_source = candidates[0][1]   # no arity match → first
        else:
            best_source = next(src for s, src in scored if s == best_score)

    # ---- Optional line-count cap ----------------------------------------
    if max_lines is not None:
        lines = best_source.splitlines()
        if len(lines) > max_lines:
            best_source = '\n'.join(lines[:max_lines]) + '\n// ... (truncated)'

    return best_source


def count_java_code_lines(source: str) -> int:
    """Count actual Java code lines in a method source string.

    Strips Javadoc (/** */), block comments (/* */), and single-line
    comments (//), then counts the remaining non-blank lines.  This is the
    fallback used for the JavaLang parser path where AST comment-node
    positions are not available.

    Args:
        source: Raw method source text (may include the method signature).

    Returns:
        Number of non-blank, non-comment lines.
    """
    if not source:
        return 0
    # Remove block/javadoc comments first (/** ... */ and /* ... */)
    stripped = _re.sub(r'/\*.*?\*/', '', source, flags=_re.DOTALL)
    # Remove single-line comments (// ...)
    stripped = _re.sub(r'//[^\n]*', '', stripped)
    return sum(1 for line in stripped.splitlines() if line.strip())
