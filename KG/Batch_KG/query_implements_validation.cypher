// Query 1: Find classes with missing implements references
// These are classes where the AST parser found 'implements' clause,
// but the referenced interfaces/classes don't exist in the graph
MATCH (j:JavaClass)
WHERE j.implementsValidationStatus = 'MISSING_REFERENCES'
  AND j.missingImplementsReferences IS NOT NULL
RETURN j.fqn, j.package, j.className, j.missingImplementsReferences, j.path
ORDER BY j.package, j.className
LIMIT 100;

// Query 2: Count missing references by interface/class name
// Shows which interfaces are most commonly missing
MATCH (j:JavaClass)
WHERE j.implementsValidationStatus = 'MISSING_REFERENCES'
UNWIND j.missingImplementsReferences AS missingRef
RETURN missingRef, count(*) AS occurences
ORDER BY occurences DESC;

// Query 3: Find all classes that implement a specific missing interface
// Replace 'InterfaceName' with the interface you're investigating
MATCH (j:JavaClass)
WHERE j.implementsValidationStatus = 'MISSING_REFERENCES'
  AND 'InterfaceName' IN j.missingImplementsReferences
RETURN j.fqn, j.path, j.missingImplementsReferences
ORDER BY j.fqn;

// Query 4: Find classes with valid implements references
// These had their implements clause successfully validated
MATCH (j:JavaClass)
WHERE j.implementsValidationStatus = 'VALID'
  AND j.implements IS NOT NULL 
  AND size(j.implements) > 0
RETURN j.fqn, j.implements
ORDER BY size(j.implements) DESC
LIMIT 50;

// Query 5: Find classes that might be implementations but have empty implements
// This catches issues where parser failed to extract implements clause
// (Use with caution - this is pattern-based, not AST-based)
MATCH (j:JavaClass)
WHERE j.isInterface = false
  AND (j.implements IS NULL OR size(j.implements) = 0)
  AND (j.className ENDS WITH 'Impl' 
       OR j.className ENDS WITH 'Implementation'
       OR j.className CONTAINS 'Default')
RETURN j.fqn, j.className, j.path
ORDER BY j.className
LIMIT 100;

// Query 6: Summary of implements validation status
MATCH (j:JavaClass)
RETURN 
  j.implementsValidationStatus AS status,
  count(*) AS count,
  collect(j.fqn)[0..5] AS sample_classes
ORDER BY count DESC;

// Query 7: Find interfaces with no implementations
// (May include external interfaces or missing implementations due to parser failures)
MATCH (interface:JavaClass)
WHERE interface.isInterface = true
WITH interface
OPTIONAL MATCH (impl:JavaClass)
WHERE interface.fqn IN impl.implements
  AND impl.implementsValidationStatus = 'VALID'
WITH interface, count(impl) AS impl_count
WHERE impl_count = 0
RETURN interface.fqn, interface.package, interface.path
ORDER BY interface.package, interface.fqn
LIMIT 100;

// Query 8: Find abstract classes that are referenced in implements
// (implements can reference both interfaces AND abstract classes)
MATCH (j:JavaClass)
WHERE j.implementsValidationStatus = 'VALID'
  AND j.implements IS NOT NULL
UNWIND j.implements AS implRef
MATCH (target:JavaClass {fqn: implRef})
WHERE target.isInterface = false  
  // If abstract classes have a property, add: AND target.isAbstract = true
RETURN DISTINCT target.fqn, target.className, count(*) AS referenced_by_count
ORDER BY referenced_by_count DESC;

// Query 9: Detailed view of a specific class's implements validation
// Replace 'com.example.ClassName' with the class FQN you want to investigate
MATCH (j:JavaClass {fqn: 'com.example.ClassName'})
RETURN j.fqn, 
       j.implements, 
       j.implementsValidationStatus, 
       j.missingImplementsReferences,
       j.isInterface,
       j.path;

// Query 10: Find packages with high percentage of missing references
// Helps identify problematic packages or external dependencies
MATCH (j:JavaClass)
WHERE j.package IS NOT NULL
WITH j.package AS pkg,
     count(*) AS total_classes,
     sum(CASE WHEN j.implementsValidationStatus = 'MISSING_REFERENCES' THEN 1 ELSE 0 END) AS missing_count
WHERE total_classes > 5  // Only show packages with at least 5 classes
RETURN pkg, 
       total_classes, 
       missing_count,
       round(100.0 * missing_count / total_classes, 2) AS missing_percentage
ORDER BY missing_percentage DESC, missing_count DESC
LIMIT 20;
