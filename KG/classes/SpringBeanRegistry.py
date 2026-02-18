from classes.DataClasses import BeanDef


from typing import Dict, List, Set, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class SpringBeanRegistry:
    """
    Central registry for all Spring beans with dual-indexed maps.
    Provides fast lookup by both beanId and beanClass.
    Uses composite keys (bean_id___bean_class) internally to prevent overwrites.
    """

    def __init__(self):
        self.beans_by_composite_key: Dict[str, BeanDef] = {}  # composite_key -> BeanDef
        self.beans_by_simple_id: Dict[str, List[str]] = {}  # bean_id -> [composite_keys]
        self.beans_by_class: Dict[str, List[BeanDef]] = {}  # Multiple beans can have same class
        self.pending_processing: Set[str] = set()  # Composite keys pending dependency processing

    @staticmethod
    def make_composite_key(bean_id: str, bean_class: str) -> str:
        """Create composite key from bean_id and bean_class"""
        return f"{bean_id}___{bean_class}"

    def add_bean(self, bean_def: BeanDef):
        """Add a bean to all indexes using composite key to prevent overwrites"""
        composite_key = self.make_composite_key(bean_def.bean_id, bean_def.bean_class)
        
        # Check if composite key already exists (should not happen)
        if composite_key in self.beans_by_composite_key:
            existing_bean = self.beans_by_composite_key[composite_key]
            logger.info(f"  Warning: Composite key '{composite_key}' already exists. Overwriting.")
            logger.info(f"    OLD Bean: XML={existing_bean.source_xml_file}")
            logger.info(f"    NEW Bean: XML={bean_def.source_xml_file}")
        
        # Add to composite key index
        self.beans_by_composite_key[composite_key] = bean_def
        
        # Add to simple ID index (for backward compatibility lookups)
        if bean_def.bean_id not in self.beans_by_simple_id:
            self.beans_by_simple_id[bean_def.bean_id] = []
        if composite_key not in self.beans_by_simple_id[bean_def.bean_id]:
            self.beans_by_simple_id[bean_def.bean_id].append(composite_key)

        # Add to class index
        if bean_def.bean_class not in self.beans_by_class:
            self.beans_by_class[bean_def.bean_class] = []
        self.beans_by_class[bean_def.bean_class].append(bean_def)

        # Mark as pending if not processed
        if not bean_def.is_dependency_processed:
            self.pending_processing.add(composite_key)

    def get_by_id(self, bean_id: str) -> Optional[BeanDef]:
        """Get bean by simple ID. Returns first match with warning if multiple beans exist."""
        composite_keys = self.beans_by_simple_id.get(bean_id, [])
        if not composite_keys:
            return None
        if len(composite_keys) > 1:
            matching_beans = [self.beans_by_composite_key[ck] for ck in composite_keys]
            logger.info(f"  Warning: Multiple beans found for ID '{bean_id}':")
            for bean in matching_beans:
                logger.info(f"    - {bean.bean_class} (XML: {bean.source_xml_file})")
            logger.info(f"    Returning first match: {matching_beans[0].bean_class}")
        return self.beans_by_composite_key[composite_keys[0]]
    
    def get_all_by_id(self, bean_id: str) -> List[BeanDef]:
        """Get all beans matching the simple ID"""
        composite_keys = self.beans_by_simple_id.get(bean_id, [])
        return [self.beans_by_composite_key[ck] for ck in composite_keys]
    
    def get_by_composite_key(self, composite_key: str) -> Optional[BeanDef]:
        """Get bean by composite key (bean_id___bean_class)"""
        return self.beans_by_composite_key.get(composite_key)

    def get_by_class(self, bean_class: str) -> List[BeanDef]:
        """Get all beans with the specified class"""
        return self.beans_by_class.get(bean_class, [])

    def mark_processed(self, bean_id: str, bean_class: str = None):
        """Mark a bean as dependency-processed. If bean_class provided, uses composite key."""
        if bean_class:
            composite_key = self.make_composite_key(bean_id, bean_class)
            if composite_key in self.beans_by_composite_key:
                self.beans_by_composite_key[composite_key].is_dependency_processed = True
                self.pending_processing.discard(composite_key)
        else:
            # Mark all beans with this ID as processed
            composite_keys = self.beans_by_simple_id.get(bean_id, [])
            for ck in composite_keys:
                if ck in self.beans_by_composite_key:
                    self.beans_by_composite_key[ck].is_dependency_processed = True
                    self.pending_processing.discard(ck)

    def has_pending(self) -> bool:
        """Check if there are beans pending processing"""
        return len(self.pending_processing) > 0

    def get_stats(self) -> Dict[str, int]:
        """Get registry statistics"""
        return {
            'total_beans': len(self.beans_by_composite_key),
            'unique_bean_ids': len(self.beans_by_simple_id),
            'unique_classes': len(self.beans_by_class),
            'pending_processing': len(self.pending_processing),
            'with_source_path': sum(1 for b in self.beans_by_composite_key.values() if b.class_source_path)
        }