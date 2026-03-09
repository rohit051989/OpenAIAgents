from neo4j import GraphDatabase

driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'Rohit@123'))
session = driver.session(database='InformationGraph')

print("=" * 80)
print("CHECKING CALL CHAIN FROM CustomerDataService.saveCustomerWithoutBean")
print("=" * 80)

# Query 1: Check what saveCustomerWithoutBean calls
query1 = """
MATCH (m1:JavaMethod {fqn: 'com.companyname.service.CustomerDataService.saveCustomerWithoutBean'})-[r:CALLS]->(m2:JavaMethod)
RETURN m2.fqn, m2.classFqn, r.resolvedFromInterface, r.originalInterface, r.requiresHumanReview
"""
result = session.run(query1)
print("\n1. saveCustomerWithoutBean calls:")
for record in result:
    print(f"   → {record['m2.fqn']}")
    print(f"      classFqn: {record['m2.classFqn']}")
    print(f"      resolvedFromInterface: {record['r.resolvedFromInterface']}")
    print(f"      originalInterface: {record['r.originalInterface']}")
    print(f"      requiresHumanReview: {record['r.requiresHumanReview']}")

# Query 2: Check if TestWithOutBeanDefination.saveCustomerWithOutBeanDefination exists
query2 = """
MATCH (m:JavaMethod)
WHERE m.fqn CONTAINS 'saveCustomerWithOutBeanDefination'
RETURN m.fqn, m.classFqn
"""
result = session.run(query2)
print("\n2. All methods with 'saveCustomerWithOutBeanDefination' in FQN:")
for record in result:
    print(f"   → {record['m.fqn']}")
    print(f"      classFqn: {record['m.classFqn']}")

# Query 3: Check what saveCustomerWithOutBeanDefination calls (should call sayHello)
query3 = """
MATCH (m1:JavaMethod)-[r:CALLS]->(m2:JavaMethod)
WHERE m1.fqn CONTAINS 'saveCustomerWithOutBeanDefination'
RETURN m1.fqn, m2.fqn, r.resolvedFromInterface
"""
result = session.run(query3)
print("\n3. saveCustomerWithOutBeanDefination calls:")
for record in result:
    print(f"   {record['m1.fqn']}")
    print(f"   → {record['m2.fqn']}")
    print(f"      resolvedFromInterface: {record['r.resolvedFromInterface']}")

# Query 4: Check if sayHello method exists
query4 = """
MATCH (m:JavaMethod)
WHERE m.methodName = 'sayHello'
RETURN m.fqn, m.classFqn
"""
result = session.run(query4)
print("\n4. sayHello methods:")
for record in result:
    print(f"   → {record['m.fqn']}")
    print(f"      classFqn: {record['m.classFqn']}")

session.close()
driver.close()

print("\n" + "=" * 80)
