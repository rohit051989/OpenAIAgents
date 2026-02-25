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
  AND c.isTestClass = FALSE
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
       }] AS CallChainWithDB;

// Query 3: For one Job, show the sequence of all “steps” in the job
MATCH (j:Job {id:'NEW-BB-FUNDING-RATES-DOWNLOAD'})-[:ENTRY]->(start)
MATCH p=(start)-[:PRECEDES*0..]->(n)
WHERE NOT (n)-[:PRECEDES]->()
RETURN p;

// Query 4: Query to find all Java methods in a specific job that perform database operations, along with the details of those operations and any resources they interact with
MATCH (j:Job)-[:CONTAINS]->(s:Step)-[:IMPLEMENTED_BY]->(c:JavaClass)-[:HAS_METHOD]->(m1:JavaMethod)
MATCH path = (m1)-[:CALLS*1..4]->(mn:JavaMethod)
WHERE c.isTestClass = FALSE 
  AND j.name = "customerProcessingJob"
  AND any(m IN nodes(path) WHERE coalesce(m.dbOperationCount, 0) > 0)

WITH j, s, c, m1, nodes(path) AS methodChain

RETURN
  j.name AS Job,
  s.name AS Step,
  c.className AS Class,
  m1.methodName AS EntryMethod,
  [m IN methodChain | {
      method: m.methodName,
      dbOps: coalesce(m.dbOperationCount, 0),
      dbDetails: m.dbOperations,
      resources: [(m)-[:DB_OPERATION]->(r:Resource) | coalesce(r.name, r.name, r.schemaName)]
  }] AS CallChainWithDBAndResources;

  // Query 5: More concise version of Query 4 focusing only on methods with DB operations and their resources
MATCH (j:Job)-[:CONTAINS]->(s:Step)-[:IMPLEMENTED_BY]->(c:JavaClass)-[:HAS_METHOD]->(m1:JavaMethod)
MATCH path = (m1)-[:CALLS*1..4]->(mn:JavaMethod)
WHERE j.name = 'customerProcessingJob'
AND c.isTestClass = FALSE
WITH j, s, c, m1, [m IN nodes(path) WHERE coalesce(m.dbOperationCount, 0) > 0] AS dbMethods
WHERE size(dbMethods) > 0

RETURN
  j.name AS Job,
  s.name AS Step,
  c.className AS Class,
  m1.methodName AS EntryMethod,
  [m IN dbMethods | {
      method: m.methodName,
      dbOps: m.dbOperationCount,
      dbDetails: m.dbOperations,
      resources: [(m)-[:DB_OPERATION]->(r:Resource) | r]
  }] AS DBMethodsWithResources;

