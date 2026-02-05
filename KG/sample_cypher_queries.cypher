MATCH path = (j:Job)-[:HAS_STEP]->(s:Step)-[:IMPLEMENTED_BY]->(c:JavaClass)
  -[:HAS_METHOD]->(m:JavaMethod)-[:CALLS*1..4]->(mn:JavaMethod)
WHERE j.name = 'YourJobName'
RETURN path
LIMIT 100