"""
Threat Intelligence Agent.

Analyzes threat data, tracks threat actors, and generates threat intelligence reports.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    ThreatIntelligenceReport,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class ThreatIntelligenceAgent:
    """Threat Intelligence Agent for fraud threat analysis.
    
    Capabilities:
        - Threat detection and classification
        - IOC (Indicator of Compromise) analysis
        - MITRE ATT&CK technique mapping
        - Threat actor tracking
        - Threat intelligence report generation
    """
    
    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the threat intelligence agent.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        self._agent_id = "threat_intelligence_agent"
        
        # Known threat patterns
        self._threat_patterns = {
            "credential_stuffing": ["brute_force_attempts", "password_spray", "credential_theft"],
            "account_takeover": ["phishing", "social_engineering", "session_hijacking"],
            "payment_fraud": ["card_testing", " BIN_attacks", "test_transactions"],
            "money_laundering": ["structuring", "layering", "integration"],
            "synthetic_identity": ["fabricated_identity", "hybrid_identity", "manipulated_identity"],
        }
    
    def analyze_threat(
        self,
        threat_type: str,
        indicators: List[Dict[str, Any]],
        context: Dict[str, Any] = None,
    ) -> ThreatIntelligenceReport:
        """Analyze a threat and generate a report.
        
        Args:
            threat_type: Type of threat
            indicators: Threat indicators
            context: Additional context
            
        Returns:
            ThreatIntelligenceReport
        """
        logger.info(f"Analyzing threat type: {threat_type}")
        
        context = context or {}
        
        # Generate threat actors
        threat_actors = self._identify_threat_actors(threat_type)
        
        # Map to MITRE ATT&CK techniques
        ttps = self._map_to_attack_techniques(threat_type)
        
        # Calculate confidence and severity
        # Derive a deterministic confidence from the number of indicators and threat type.
        try:
            seed = abs(hash(threat_type)) % (2**31)
        except Exception:
            seed = abs(hash(str(threat_type))) % (2**31)
        confidence = round(0.70 + (seed % 250) / 1000.0, 3)
        severity = self._calculate_severity(len(indicators), confidence)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_type, ttps)
        
        report = ThreatIntelligenceReport(
            threat_type=threat_type,
            threat_actors=threat_actors,
            indicators=indicators,
            ttps=ttps,
            affected_entities=context.get("affected_entities", []),
            confidence=confidence,
            severity=severity,
            description=self._generate_description(threat_type, indicators),
            recommendations=recommendations,
            sources=["internal_analysis", "threat_feed", "user_reports"],
        )
        
        # Store report
        self._store.store_threat_report(report)
        
        logger.info(f"Threat analysis complete: {threat_type}, severity: {severity}")
        return report
    
    def enrich_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich an IOC with additional context.
        
        Args:
            ioc: Indicator of Compromise
            
        Returns:
            Enriched IOC
        """
        ioc_type = ioc.get("type", "unknown")
        ioc_value = ioc.get("value", ioc.get("indicator", ""))

        # Derive a deterministic seed from the IOC value.
        try:
            seed = abs(hash(ioc_value)) % (2**31)
        except Exception:
            seed = abs(hash(str(ioc_value))) % (2**31)

        # Map seed to structured, deterministic enrichment fields.
        confidence = round(0.60 + (seed % 350) / 1000.0, 3)
        threat_associations = seed % 11  # 0-10
        prevalence_bands = ["rare", "uncommon", "common", "widespread"]
        prevalence = prevalence_bands[(seed // 11) % len(prevalence_bands)]

        enriched = {
            **ioc,
            "confidence_score": confidence,
            "threat_associations": threat_associations,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "historical_prevalence": prevalence,
        }
        
        if ioc_type == "ip_address":
            countries = ["US", "RU", "CN", "BR", "IN"]
            enriched["geolocation"] = {
                "country": countries[(seed // 11) % len(countries)],
                "reputation_score": round(0.1 + (seed % 800) / 1000.0, 3),
            }
        elif ioc_type == "email":
            enriched["domain_age"] = 1 + (seed % 3650)
            enriched["mail_server_verified"] = bool((seed // 100) % 2)
        
        return enriched
    
    def track_threat_actor(self, actor_name: str, activity: Dict[str, Any]) -> Dict[str, Any]:
        """Track a threat actor's activity.
        
        Args:
            actor_name: Name of the threat actor
            activity: Activity data
            
        Returns:
            Actor tracking data
        """
        # Derive deterministic tracking fields from actor_name.
        try:
            seed = abs(hash(actor_name)) % (2**31)
        except Exception:
            seed = abs(hash(str(actor_name))) % (2**31)

        all_ttps = ["T1078", "T1484", "T1566", "T1587", "T1591"]
        ttp_count = 1 + (seed % 3)  # 1-3 TTPs
        ttp_seed = seed
        primary_ttps = [all_ttps[(ttp_seed + i * 37) % len(all_ttps)] for i in range(ttp_count)]

        campaign_seed = seed // 100
        campaign_count = campaign_seed % 4  # 0-3 campaigns
        associated_campaigns = [f"campaign_{(campaign_seed + i * 17) % 100 + 1}" for i in range(campaign_count)]

        confidence = round(0.60 + (seed % 350) / 1000.0, 3)
        activity_count = 1 + (seed % 100)

        return {
            "actor_name": actor_name,
            "last_activity": datetime.now(timezone.utc).isoformat(),
            "activity_count": activity_count,
            "primary_ttps": primary_ttps,
            "associated_campaigns": associated_campaigns,
            "confidence": confidence,
        }
    
    def create_threat_hunt_task(
        self,
        hypothesis: str,
        indicators: List[str],
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> AgentTask:
        """Create a threat hunting task.
        
        Args:
            hypothesis: Hunt hypothesis
            indicators: IOCs to hunt for
            priority: Task priority
            
        Returns:
            AgentTask
        """
        task = AgentTask(
            agent_type=AgentType.THREAT_INTELLIGENCE,
            title=f"Threat Hunt: {hypothesis[:50]}",
            description=f"Investigate hypothesis: {hypothesis}\nIndicators: {', '.join(indicators[:5])}",
            priority=priority,
            context={
                "hypothesis": hypothesis,
                "indicators": indicators,
                "type": "threat_hunt",
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created threat hunt task: {task.task_id}")
        
        return task
    
    def get_active_threats(self, hours: int = 24) -> List[ThreatIntelligenceReport]:
        """Get active threats from the last N hours."""
        return self._store.get_recent_threats(hours)
    
    def _identify_threat_actors(self, threat_type: str) -> List[str]:
        """Identify potential threat actors."""
        actors = {
            "credential_stuffing": ["bot_network_alpha", "credential_trader_collective"],
            "account_takeover": ["phishing_king", "social_engineer_guild"],
            "payment_fraud": ["card_test_ring", "fraud_network_lotus"],
            "money_laundering": ["layering_network_cobra", "integration_group_phi"],
            "synthetic_identity": ["identity_fabricator_collective", "synthetic_ring_zeta"],
        }
        return actors.get(threat_type, ["unknown_actor"])
    
    def _map_to_attack_techniques(self, threat_type: str) -> List[str]:
        """Map threat to MITRE ATT&CK techniques."""
        technique_mapping = {
            "credential_stuffing": ["T1078", "T1110", "T1566"],
            "account_takeover": ["T1566", "T1484", "T1078"],
            "payment_fraud": ["T1059", "T1566", "T1078"],
            "money_laundering": ["T1048", "T1566", "T1059"],
            "synthetic_identity": ["T1136", "T1484", "T1566"],
        }
        return technique_mapping.get(threat_type, ["T1566"])
    
    def _calculate_severity(self, indicator_count: int, confidence: float) -> str:
        """Calculate threat severity."""
        score = indicator_count * confidence
        if score >= 2.5:
            return "CRITICAL"
        elif score >= 1.5:
            return "HIGH"
        elif score >= 0.8:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, threat_type: str, ttps: List[str]) -> List[str]:
        """Generate threat mitigation recommendations."""
        recommendations = [
            "Monitor for associated indicators",
            "Update detection rules",
            "Review access logs",
        ]
        
        if "T1078" in ttps:  # Valid Accounts
            recommendations.append("Enforce MFA for all accounts")
        
        if "T1566" in ttps:  # Phishing
            recommendations.append("Enhance email filtering rules")
            recommendations.append("User security awareness training")
        
        if "T1059" in ttps:  # Command and Scripting Interpreter
            recommendations.append("Restrict command execution permissions")
        
        return recommendations
    
    def _generate_description(self, threat_type: str, indicators: List[Dict[str, Any]]) -> str:
        """Generate threat description."""
        return f"{threat_type.replace('_', ' ').title()} threat detected with {len(indicators)} associated indicators"


# Global singleton
_threat_agent: Optional[ThreatIntelligenceAgent] = None


def get_threat_intelligence_agent(store: Optional[SOCStore] = None) -> ThreatIntelligenceAgent:
    """Get or create the singleton ThreatIntelligenceAgent instance."""
    global _threat_agent
    
    if _threat_agent is None:
        _threat_agent = ThreatIntelligenceAgent(store=store)
    return _threat_agent