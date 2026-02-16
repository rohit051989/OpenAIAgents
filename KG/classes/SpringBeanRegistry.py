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
    """

    def __init__(self):
        self.beans_by_id: Dict[str, BeanDef] = {}
        self.beans_by_class: Dict[str, List[BeanDef]] = {}  # Multiple beans can have same class
        self.pending_processing: Set[str] = set()  # Bean IDs pending dependency processing

    def add_bean(self, bean_def: BeanDef):
        """Add a bean to both indexes"""
        # Add to ID index
        if bean_def.bean_id in self.beans_by_id:
            existing_bean = self.beans_by_id[bean_def.bean_id]
            logger.info(f"  Warning: Bean ID '{bean_def.bean_id}' already exists. Overwriting.")
            logger.info(f"    OLD Bean: {existing_bean}")
            logger.info(f"    NEW Bean: {bean_def}")
        self.beans_by_id[bean_def.bean_id] = bean_def

        # Add to class index
        if bean_def.bean_class not in self.beans_by_class:
            self.beans_by_class[bean_def.bean_class] = []
        self.beans_by_class[bean_def.bean_class].append(bean_def)

        # Mark as pending if not processed
        if not bean_def.is_dependency_processed:
            self.pending_processing.add(bean_def.bean_id)

    def get_by_id(self, bean_id: str) -> Optional[BeanDef]:
        """Get bean by ID"""
        return self.beans_by_id.get(bean_id)

    def get_by_class(self, bean_class: str) -> List[BeanDef]:
        """Get all beans with the specified class"""
        return self.beans_by_class.get(bean_class, [])

    def mark_processed(self, bean_id: str):
        """Mark a bean as dependency-processed"""
        if bean_id in self.beans_by_id:
            self.beans_by_id[bean_id].is_dependency_processed = True
            self.pending_processing.discard(bean_id)

    def has_pending(self) -> bool:
        """Check if there are beans pending processing"""
        return len(self.pending_processing) > 0

    def get_stats(self) -> Dict[str, int]:
        """Get registry statistics"""
        return {
            'total_beans': len(self.beans_by_id),
            'unique_classes': len(self.beans_by_class),
            'pending_processing': len(self.pending_processing),
            'with_source_path': sum(1 for b in self.beans_by_id.values() if b.class_source_path)
        }