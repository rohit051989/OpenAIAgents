from classes.DataClasses import ClassInfo, DBOperation

from typing import Dict, List


class LLMDAOAnalyzer:
    """Analyzes DAO methods using LLM to extract database operations"""

    def __init__(self, config: dict):
        """Initialize LLM analyzer with configuration"""
        self.config = config
        self.provider = config.get('provider', 'openai')
        self.model = config.get('model', 'gpt-4')
        self.temperature = config.get('temperature', 0.1)
        self.max_tokens = config.get('max_tokens', 2000)
        self.timeout = config.get('timeout', 30)

        # Initialize cache
        self.cache = {}
        self.cache_file = config.get('cache_file', '.db_operation_cache.json')
        if config.get('cache_results', True):
            self._load_cache()

        # Initialize LLM client
        self._init_llm_client()

    def _init_llm_client(self):
        """Initialize the appropriate LLM client based on provider"""
        import os

        if self.provider == 'openai':
            try:
                from openai import OpenAI
                api_key = os.getenv(self.config.get('api_key_env', 'OPENAI_API_KEY'))
                if not api_key:
                    raise ValueError(f"API key not found in environment variable: {self.config.get('api_key_env')}")
                self.client = OpenAI(api_key=api_key)
            except ImportError:
                raise ImportError("OpenAI package not installed. Run: pip install openai")

        elif self.provider == 'anthropic':
            try:
                from anthropic import Anthropic
                api_key = os.getenv(self.config.get('api_key_env', 'ANTHROPIC_API_KEY'))
                if not api_key:
                    raise ValueError(f"API key not found in environment variable: {self.config.get('api_key_env')}")
                self.client = Anthropic(api_key=api_key)
            except ImportError:
                raise ImportError("Anthropic package not installed. Run: pip install anthropic")

        elif self.provider == 'bedrock':
            try:
                import boto3
                self.client = boto3.client('bedrock-runtime', region_name=self.config.get('aws_region', 'us-east-1'))
            except ImportError:
                raise ImportError("Boto3 package not installed. Run: pip install boto3")

        elif self.provider == 'ollama':
            # Local Ollama doesn't need API key
            self.client = None

        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _load_cache(self):
        """Load cached results from file"""
        import json
        from pathlib import Path

        cache_path = Path(self.cache_file)
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                print(f"  Loaded {len(self.cache)} cached DB operation analyses")
            except Exception as e:
                print(f"  Warning: Failed to load cache: {e}")
                self.cache = {}

    def _save_cache(self):
        """Save results to cache file"""
        import json

        if not self.config.get('cache_results', True):
            return

        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"  Warning: Failed to save cache: {e}")

    def analyze_dao_class(self, class_info: ClassInfo) -> Dict[str, List[DBOperation]]:
        """
        Analyze all methods in a DAO class using LLM.
        Returns: Dict[method_name, List[DBOperation]]
        """
        # Check cache first
        cache_key = f"{class_info.fqn}:{class_info.source_path}"
        if cache_key in self.cache:
            print(f"    ✓ Using cached analysis for {class_info.class_name}")
            return self._deserialize_operations(self.cache[cache_key], class_info)

        # Read source file
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            print(f"    Error reading source file: {e}")
            return {}

        # Prepare prompt
        prompt = self._create_analysis_prompt(class_info, source_code)

        # Call LLM
        print(f"    🤖 Analyzing {class_info.class_name} with {self.provider}/{self.model}...")
        try:
            analysis_result = self._call_llm(prompt)

            # Parse LLM response
            operations_by_method = self._parse_llm_response(analysis_result, class_info)

            # Cache the result
            self.cache[cache_key] = self._serialize_operations(operations_by_method)
            self._save_cache()

            return operations_by_method

        except Exception as e:
            print(f"    ⚠️  LLM analysis failed: {e}")
            return {}

    def _create_analysis_prompt(self, class_info: ClassInfo, source_code: str) -> str:
        """Create prompt for LLM analysis"""
        method_list = "\n".join([f"  - {name}: {m.signature}" for name, m in class_info.methods.items()])

        prompt = f"""You are a Java code analyzer specializing in database operations. Analyze the following DAO class and identify all database operations.

**Class Information:**
- FQN: {class_info.fqn}
- Class Name: {class_info.class_name}
- Methods:
{method_list}

**Source Code:**
```java
{source_code}
```

**Task:**
For each method in this class, determine:
1. Does it perform database operations? (yes/no)
2. If yes, what type of operation? (SELECT, INSERT, UPDATE, DELETE)
3. What table(s) are being accessed?
4. What is your confidence level? (HIGH, MEDIUM, LOW)

**Output Format (JSON):**
Return a JSON array where each element represents a method's DB operations:
```json
[
  {{
    "method_name": "getJobDetails",
    "has_db_operation": true,
    "operations": [
      {{
        "operation_type": "SELECT",
        "table_name": "BATCH_JOBS",
        "confidence": "HIGH",
        "evidence": "Uses jdbcTemplate.queryForObject with SQL constant from IFrameWorkDBQueries.FETCH_JOB_DETAILS"
      }}
    ]
  }},
  {{
    "method_name": "helperMethod",
    "has_db_operation": false,
    "operations": []
  }}
]
```

**Important Notes:**
- Look for Spring JDBC (JdbcTemplate, NamedParameterJdbcTemplate)
- Look for JPA (EntityManager, persist, merge, find, remove)
- Look for Hibernate (Session, save, update, delete, createQuery)
- Look for JDBC (Connection, PreparedStatement, executeQuery, executeUpdate)
- For SQL constants, analyze the constant class if referenced
- Extract actual table names from SQL queries (FROM, INTO, UPDATE clauses)
- Be conservative: if unsure, mark confidence as LOW
- Return ONLY the JSON array, no additional text

Analyze now:"""

        return prompt

    def _call_llm(self, prompt: str) -> str:
        """Call the LLM API"""
        if self.provider == 'openai':
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a Java code analyzer. Return only valid JSON responses."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=self.timeout
            )
            return response.choices[0].message.content.strip()

        elif self.provider == 'anthropic':
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text.strip()

        elif self.provider == 'bedrock':
            import json
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            })
            response = self.client.invoke_model(
                modelId=self.model,
                body=body
            )
            response_body = json.loads(response['body'].read())
            return response_body['content'][0]['text'].strip()

        elif self.provider == 'ollama':
            import requests
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens
                    }
                },
                timeout=self.timeout
            )
            return response.json()['response'].strip()

        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _parse_llm_response(self, response: str, class_info: ClassInfo) -> Dict[str, List[DBOperation]]:
        """Parse LLM JSON response into DBOperation objects"""
        import json
        import re

        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find JSON array
            json_match = re.search(r'\[\s*{[\s\S]*}\s*\]', response)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_str = response

        try:
            analysis_data = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"    ⚠️  Failed to parse LLM response as JSON: {e}")
            print(f"    Response: {response[:200]}...")
            return {}

        operations_by_method = {}

        for method_analysis in analysis_data:
            method_name = method_analysis.get('method_name')
            has_db_operation = method_analysis.get('has_db_operation', False)

            if not method_name or not has_db_operation:
                continue

            operations = []
            for op_data in method_analysis.get('operations', []):
                db_op = DBOperation(
                    operation_type=op_data.get('operation_type', 'UNKNOWN'),
                    table_name=op_data.get('table_name'),
                    entity_type=None,
                    method_fqn=f"{class_info.fqn}.{method_name}",
                    confidence=op_data.get('confidence', 'MEDIUM'),
                    raw_query=op_data.get('evidence')
                )
                operations.append(db_op)

            if operations:
                operations_by_method[method_name] = operations

        return operations_by_method

    def _serialize_operations(self, operations_by_method: Dict[str, List[DBOperation]]) -> dict:
        """Serialize operations for caching"""
        serialized = {}
        for method_name, ops in operations_by_method.items():
            serialized[method_name] = [
                {
                    'operation_type': op.operation_type,
                    'table_name': op.table_name,
                    'entity_type': op.entity_type,
                    'confidence': op.confidence,
                    'raw_query': op.raw_query
                }
                for op in ops
            ]
        return serialized

    def _deserialize_operations(self, cached_data: dict, class_info: ClassInfo) -> Dict[str, List[DBOperation]]:
        """Deserialize cached operations"""
        operations_by_method = {}
        for method_name, ops_data in cached_data.items():
            operations = [
                DBOperation(
                    operation_type=op['operation_type'],
                    table_name=op['table_name'],
                    entity_type=op.get('entity_type'),
                    method_fqn=f"{class_info.fqn}.{method_name}",
                    confidence=op['confidence'],
                    raw_query=op.get('raw_query')
                )
                for op in ops_data
            ]
            operations_by_method[method_name] = operations
        return operations_by_method