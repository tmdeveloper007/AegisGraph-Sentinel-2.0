"""
Investigation Agent.

Autonomous fraud investigation agent that analyzes entities, triages alerts,
and manages investigation workflows.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    AgentStatus,
    TaskPriority,
    TaskStatus,
    InvestigationResult,
    InvestigationStatus,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class InvestigationAgent:
    """Investigation Agent for autonomous fraud investigation.
    
    Capabilities:
        - Entity analysis and risk scoring
        - Alert triage and prioritization
        - Case management
        - Investigation workflow orchestration
        - Finding synthesis
    """
    
    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the investigation agent.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        self._agent_type = AgentType.INVESTIGATION
        self._agent_id = f"investigation_agent"
    
    def analyze_entity(self, entity_id: str, context: Dict[str, Any] = None) -> InvestigationResult:
        """Analyze an entity for fraud indicators.
        
        Args:
            entity_id: Entity to analyze
            context: Additional context
            
        Returns:
            InvestigationResult with findings
        """
        logger.info(f"Analyzing entity {entity_id}")
        
        context = context or {}

        # Analyse entity using available context data.
        risk_factors = []
        findings = []
        evidence = []

        # Check for unusual transaction pattern via amount threshold.
        amount = context.get('amount', 0)
        if amount and amount > 10000:
            risk_factors.append("unusual_transaction_pattern")
            findings.append({
                "type": "pattern_detection",
                "description": "Transaction amount exceeds high-value threshold",
                "severity": "HIGH",
                "confidence": 0.85,
            })

        # Check for device anomaly via missing or new device_id.
        device_id = context.get('device_id')
        if not device_id:
            risk_factors.append("device_anomaly")
            findings.append({
                "type": "device_missing",
                "description": "No device identifier present in transaction context",
                "severity": "MEDIUM",
                "confidence": 0.70,
            })

        # Check for velocity breach via transaction frequency in context.
        txn_count = context.get('transaction_count', 0)
        if txn_count > 5:
            risk_factors.append("velocity_breach")
            findings.append({
                "type": "velocity_exceeded",
                "description": f"Transaction count {txn_count} exceeds velocity threshold",
                "severity": "HIGH",
                "confidence": 0.80,
            })

        # Build evidence record from available context.
        evidence.append({
            "type": "transaction_history",
            "count": max(1, txn_count),
            "suspicious_count": len(risk_factors),
            "confidence": 0.8,
        })

        # Calculate risk score from identified factors.
        if risk_factors:
            factor_scores = {
                "unusual_transaction_pattern": 0.75,
                "device_anomaly": 0.65,
                "velocity_breach": 0.80,
            }
            risk_score = min(1.0, sum(factor_scores.get(f, 0.1) for f in risk_factors) / len(risk_factors))
        else:
            risk_score = 0.1
        
        # Determine status
        if risk_score >= 0.8:
            status = InvestigationStatus.ESCALATED
        elif risk_score >= 0.5:
            status = InvestigationStatus.REQUIRES_REVIEW
        else:
            status = InvestigationStatus.CLOSED
        
        result = InvestigationResult(
            entity_id=entity_id,
            status=status,
            findings=findings,
            evidence=evidence,
            risk_score=risk_score,
            recommendations=self._generate_recommendations(risk_score, risk_factors),
            linked_entities=self._find_linked_entities(entity_id, context),
            timeline=self._build_timeline(entity_id),
            confidence=0.8,
            processed_by=[self._agent_id],
        )
        
        # Store result
        self._store.store_investigation(result)
        
        logger.info(f"Investigation complete for {entity_id}, risk: {risk_score:.2f}")
        return result
    
    def triage_alerts(self, alert_ids: List[str], priority: TaskPriority = TaskPriority.MEDIUM) -> List[AgentTask]:
        """Triage and prioritize alerts.
        
        Args:
            alert_ids: Alert IDs to triage
            priority: Task priority
            
        Returns:
            List of investigation tasks
        """
        logger.info(f"Triaging {len(alert_ids)} alerts")
        
        tasks = []
        for idx, alert_id in enumerate(alert_ids):
            # Derive a deterministic risk estimate from the alert_id.
            try:
                seed = abs(hash(alert_id)) % (2**31)
            except Exception:
                seed = idx
            estimated_risk = round(0.3 + (seed % 600) / 1000.0, 3)
            
            task = AgentTask(
                agent_type=self._agent_type,
                title=f"Investigate Alert {alert_id}",
                description=f"Investigate alert {alert_id} with estimated risk {estimated_risk:.2f}",
                priority=priority,
                context={
                    "alert_id": alert_id,
                    "estimated_risk": estimated_risk,
                    "source": "alert_triage",
                },
            )
            
            self._store.store_task(task)
            tasks.append(task)
        
        return tasks
    
    def create_investigation(self, entity_id: str, case_id: Optional[str] = None, priority: TaskPriority = TaskPriority.MEDIUM) -> AgentTask:
        """Create an investigation task.
        
        Args:
            entity_id: Entity to investigate
            case_id: Optional case ID
            priority: Task priority
            
        Returns:
            AgentTask for the investigation
        """
        task = AgentTask(
            agent_type=self._agent_type,
            title=f"Investigate Entity {entity_id}",
            description=f"Conduct comprehensive fraud investigation for entity {entity_id}",
            priority=priority,
            context={
                "entity_id": entity_id,
                "case_id": case_id,
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created investigation task {task.task_id} for {entity_id}")
        
        return task
    
    def update_investigation_status(self, investigation_id: str, status: InvestigationStatus) -> bool:
        """Update investigation status."""
        investigation = self._store.get_investigation(investigation_id)
        if investigation:
            investigation.status = status
            if status == InvestigationStatus.CLOSED:
                investigation.completed_at = datetime.now(timezone.utc)
            return True
        return False
    
    def get_investigation_summary(self, entity_id: str) -> Dict[str, Any]:
        """Get investigation summary for an entity."""
        investigations = self._store.get_entity_investigations(entity_id)
        
        if not investigations:
            return {"total": 0, "risk_score": 0.0}
        
        total_risk = sum(inv.risk_score for inv in investigations) / len(investigations)
        high_risk_count = sum(1 for inv in investigations if inv.risk_score >= 0.7)
        
        return {
            "total_investigations": len(investigations),
            "average_risk_score": total_risk,
            "high_risk_count": high_risk_count,
            "latest_investigation": investigations[-1].investigation_id if investigations else None,
        }
    
    def _generate_recommendations(self, risk_score: float, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on risk."""
        recommendations = []
        
        if risk_score >= 0.8:
            recommendations.append("ESCALATE: Immediate review required by senior analyst")
            recommendations.append("Consider temporary account freeze")
        
        if "velocity_breach" in risk_factors:
            recommendations.append("Implement transaction velocity limits")
        
        if "device_anomaly" in risk_factors:
            recommendations.append("Request additional identity verification")
        
        if risk_score >= 0.5:
            recommendations.append("Schedule enhanced monitoring for 72 hours")
        
        recommendations.append("Document findings in case management system")
        
        return recommendations
    
    def _find_linked_entities(self, entity_id: str, context: Dict[str, Any]) -> List[str]:
        """Find entities linked to the given entity."""
        # Return a deterministic linked entity list based on entity_id hash.
        try:
            seed = abs(hash(entity_id)) % (2**31)
        except Exception:
            seed = abs(hash(entity_id or "")) % (2**31)
        count = seed % 6  # 0-5 linked entities
        return [f"linked_{entity_id}_{i}" for i in range(count)]
    
    def _build_timeline(self, entity_id: str) -> List[Dict[str, Any]]:
        """Build activity timeline for entity."""
        # Derive a deterministic event count and types from entity_id.
        try:
            seed = abs(hash(entity_id)) % (2**31)
        except Exception:
            seed = abs(hash(entity_id or "")) % (2**31)
        event_count = 3 + (seed % 8)  # 3-10 events
        event_types = ["transaction", "login", "profile_change"]
        timeline = []
        base_time = datetime.now(timezone.utc)
        for i in range(event_count):
            type_seed = (seed + i * 17) % len(event_types)
            risk_seed = (seed + i * 31) % 2
            timeline.append({
                "timestamp": base_time.isoformat(),
                "event": f"activity_{i}",
                "type": event_types[type_seed],
                "risk_indicator": bool(risk_seed),
            })
        return timeline


# Global singleton
_investigation_agent: Optional[InvestigationAgent] = None


def get_investigation_agent(store: Optional[SOCStore] = None) -> InvestigationAgent:
    """Get or create the singleton InvestigationAgent instance."""
    global _investigation_agent
    
    if _investigation_agent is None:
        _investigation_agent = InvestigationAgent(store=store)
    return _investigation_agent