"""Unit tests for app.core.security — Cypher safety validation.

These tests require no external services and run fully in-process.
"""

import pytest

from app.core.security import is_read_only_cypher


class TestIsReadOnlyCypher:
    # ------------------------------------------------------------------ safe
    def test_simple_match_is_allowed(self):
        assert is_read_only_cypher("MATCH (n:Job) RETURN n") is True

    def test_match_with_where_is_allowed(self):
        query = "MATCH (j:Job) WHERE j.enabled = true RETURN j.name"
        assert is_read_only_cypher(query) is True

    def test_call_db_labels_is_allowed(self):
        assert is_read_only_cypher("CALL db.labels() YIELD label RETURN label") is True

    def test_return_only_is_allowed(self):
        assert is_read_only_cypher("RETURN 1 AS one") is True

    def test_unwind_with_return_is_allowed(self):
        assert is_read_only_cypher("UNWIND [1,2,3] AS x RETURN x") is True

    def test_with_match_is_allowed(self):
        query = "WITH 'hello' AS greeting MATCH (n) RETURN n"
        assert is_read_only_cypher(query) is True

    def test_leading_whitespace_is_handled(self):
        assert is_read_only_cypher("   MATCH (n) RETURN n") is True

    # --------------------------------------------------------------- unsafe
    def test_create_is_blocked(self):
        assert is_read_only_cypher("CREATE (n:Job {id: 'x'})") is False

    def test_merge_is_blocked(self):
        assert is_read_only_cypher("MERGE (n:Job {id: 'x'}) RETURN n") is False

    def test_set_is_blocked(self):
        assert is_read_only_cypher("MATCH (n) SET n.name = 'test'") is False

    def test_delete_is_blocked(self):
        assert is_read_only_cypher("MATCH (n) DELETE n") is False

    def test_remove_is_blocked(self):
        assert is_read_only_cypher("MATCH (n) REMOVE n.name") is False

    def test_drop_is_blocked(self):
        assert is_read_only_cypher("DROP INDEX job_idx") is False

    def test_call_dbms_is_blocked(self):
        assert is_read_only_cypher("CALL dbms.listQueries()") is False

    def test_call_apoc_write_is_blocked(self):
        assert is_read_only_cypher("CALL apoc.create.node(['Job'], {id:'x'})") is False

    def test_semicolon_is_blocked(self):
        # Multiple statements via semicolon are not allowed
        assert is_read_only_cypher("MATCH (n) RETURN n; MATCH (m) RETURN m") is False

    def test_empty_string_is_blocked(self):
        assert is_read_only_cypher("") is False

    def test_whitespace_only_is_blocked(self):
        assert is_read_only_cypher("   ") is False

    def test_match_with_embedded_create_is_blocked(self):
        # Sneaking CREATE inside a MATCH-starting query must be caught
        query = "MATCH (n) WHERE n.name = 'x' CREATE (m:Fake) RETURN m"
        assert is_read_only_cypher(query) is False
