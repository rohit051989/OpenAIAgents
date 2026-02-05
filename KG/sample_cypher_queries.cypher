// Sample Cypher Queries for Neo4j Java Code Analysis

// Query 1: Visualize the call hierarchy of Java methods within a specific job
MATCH path = (j:Job)-[:CONTAINS]->(s:Step)-[:IMPLEMENTED_BY]->(c:JavaClass)
  -[:HAS_METHOD]->(m:JavaMethod)-[:CALLS*1..4]->(mn:JavaMethod)
WHERE j.name = 'YourJobName'
RETURN path
LIMIT 100;

// Query 2: Identify Java methods that perform database operations within a job's steps
MATCH (j:Job)-[:CONTAINS]->(s:Step)-[:IMPLEMENTED_BY]->(c:JavaClass)-[:HAS_METHOD]->(m1:JavaMethod)
MATCH path = (m1)-[:CALLS*1..4]->(mn:JavaMethod)
WHERE j.name = 'YourJobName'
  AND any(m IN nodes(path) WHERE m.dbOperationCount > 0)
WITH j, s, c, m1, nodes(path) AS methodChain, path
RETURN j.name AS Job,
       s.name AS Step,
       c.className AS Class,
       m1.methodName AS EntryMethod,
       [m IN methodChain | {
         method: m.methodName, 
         dbOps: m.dbOperationCount,
         dbDetails: m.dbOperations
       }] AS CallChainWithDB