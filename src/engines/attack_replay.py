#!/usr/bin/env python3
"""
Live Attack Replay System for LogSentinel Pro v3.0
Records, stores, and replays attack sequences for analysis and investigation
"""

import json
import uuid
import hashlib
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from pathlib import Path
import threading


@dataclass
class AttackEvent:
    """Single event in an attack sequence."""
    event_id: str
    timestamp: str
    event_type: str  # login_attempt, port_scan, sql_injection, etc.
    source_ip: str
    destination_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    payload: Optional[Dict]
    detection_method: str
    severity: str
    description: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AttackSequence:
    """Collection of related attack events."""
    sequence_id: str
    attack_name: str
    start_time: str
    end_time: Optional[str]
    events: List[AttackEvent] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    target_hosts: List[str] = field(default_factory=list)
    attack_type: str = "unknown"  # brute_force, ddos, injection, privilege_escalation, etc.
    severity: str = "unknown"
    status: str = "in_progress"  # in_progress, concluded, contained
    mitre_tactics: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        data = asdict(self)
        data["events"] = [e.to_dict() for e in self.events]
        return data
    
    def duration_seconds(self) -> Optional[float]:
        """Get attack duration in seconds."""
        if self.end_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            return (end - start).total_seconds()
        return None


class AttackReplaySystem:
    """Record and replay attack sequences."""
    
    def __init__(self, replay_data_dir: Optional[str] = None):
        self.replay_dir = Path(replay_data_dir or Path.home() / ".local/share/LogSentinel Pro/attack_replays")
        self.replay_dir.mkdir(parents=True, exist_ok=True)
        
        self.active_sequences: Dict[str, AttackSequence] = {}
        self.completed_sequences: Dict[str, AttackSequence] = {}
        self.sequence_lock = threading.Lock()
        self.replay_listeners: List[Callable] = []
        
        self._load_persisted_sequences()
    
    def _load_persisted_sequences(self) -> None:
        """Load previously saved attack sequences from disk."""
        if not self.replay_dir.exists():
            return
        
        for replay_file in self.replay_dir.glob("*.json"):
            try:
                with open(replay_file, 'r') as f:
                    sequence_data = json.load(f)
                    # Reconstruct objects (simplified loading)
            except Exception as e:
                print(f"Error loading replay: {e}")
    
    def detect_attack_sequence(self,
                              event_type: str,
                              source_ip: str,
                              destination_ip: Optional[str],
                              port: Optional[int],
                              severity: str,
                              description: str,
                              payload: Optional[Dict] = None) -> Optional[str]:
        """
        Detect and correlate events into attack sequences.
        Returns sequence_id if a new sequence is started.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        event = AttackEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            port=port,
            protocol=self._infer_protocol(port) if port else None,
            payload=payload,
            detection_method="correlation",
            severity=severity,
            description=description
        )
        
        # Try to correlate with existing sequences
        with self.sequence_lock:
            correlated_sequence = self._correlate_event(event)
            
            if correlated_sequence:
                correlated_sequence.events.append(event)
                self._notify_replay_listeners(correlated_sequence, "event_added")
                return correlated_sequence.sequence_id
            else:
                # Determine if this starts a new sequence
                if self._is_attack_starter(event):
                    sequence_id = str(uuid.uuid4())
                    new_sequence = AttackSequence(
                        sequence_id=sequence_id,
                        attack_name=self._infer_attack_name(event_type),
                        start_time=timestamp,
                        events=[event],
                        source_ips=[source_ip],
                        target_hosts=[destination_ip] if destination_ip else [],
                        attack_type=self._infer_attack_type(event_type),
                        severity=severity
                    )
                    
                    self.active_sequences[sequence_id] = new_sequence
                    self._notify_replay_listeners(new_sequence, "sequence_started")
                    return sequence_id
        
        return None
    
    def _correlate_event(self, event: AttackEvent) -> Optional[AttackSequence]:
        """Correlate event with existing attack sequences."""
        # Look for sequences with same source IP within time window
        time_threshold = datetime.now() - timedelta(minutes=10)
        
        for sequence in self.active_sequences.values():
            if event.source_ip in sequence.source_ips:
                if datetime.fromisoformat(sequence.start_time) > time_threshold:
                    return sequence
        
        return None
    
    def _is_attack_starter(self, event: AttackEvent) -> bool:
        """Determine if event could start a new attack sequence."""
        attack_starters = [
            "port_scan", "brute_force", "sql_injection",
            "xss_attempt", "credential_stuffing", "privilege_escalation",
            "lateral_movement", "data_exfiltration", "malware_execution"
        ]
        return event.event_type in attack_starters
    
    def _infer_attack_name(self, event_type: str) -> str:
        """Generate attack name from event type."""
        return f"Attack: {event_type.replace('_', ' ').title()}"
    
    def _infer_attack_type(self, event_type: str) -> str:
        """Categorize attack type."""
        type_mapping = {
            "port_scan": "reconnaissance",
            "brute_force": "credential_access",
            "sql_injection": "execution",
            "xss_attempt": "execution",
            "privilege_escalation": "privilege_escalation",
            "lateral_movement": "lateral_movement",
            "data_exfiltration": "exfiltration",
            "malware_execution": "execution",
            "ddos": "impact"
        }
        return type_mapping.get(event_type, "unknown")
    
    def _infer_protocol(self, port: int) -> Optional[str]:
        """Infer protocol from port number."""
        port_protocols = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            445: "SMB",
            3389: "RDP",
            25: "SMTP",
            53: "DNS"
        }
        return port_protocols.get(port)
    
    def conclude_sequence(self, sequence_id: str, status: str = "contained") -> Optional[AttackSequence]:
        """Mark an attack sequence as concluded."""
        with self.sequence_lock:
            if sequence_id not in self.active_sequences:
                return None
            
            sequence = self.active_sequences[sequence_id]
            sequence.end_time = datetime.now().isoformat()
            sequence.status = status
            
            # Map to MITRE ATT&CK
            sequence.mitre_tactics = self._map_mitre_tactics(sequence.attack_type)
            
            # Move to completed
            self.completed_sequences[sequence_id] = sequence
            del self.active_sequences[sequence_id]
            
            # Save to disk
            self._persist_sequence(sequence)
            
            self._notify_replay_listeners(sequence, "sequence_concluded")
        
        return sequence
    
    def _map_mitre_tactics(self, attack_type: str) -> List[str]:
        """Map attack type to MITRE ATT&CK tactics."""
        mitre_mapping = {
            "reconnaissance": ["T1592", "T1589", "T1590"],
            "credential_access": ["T1110", "T1555", "T1187"],
            "execution": ["T1059", "T1059.001", "T1059.003"],
            "privilege_escalation": ["T1548", "T1547", "T1547.001"],
            "lateral_movement": ["T1570", "T1021", "T1021.006"],
            "exfiltration": ["T1041", "T1020", "T1030"],
            "impact": ["T1531", "T1561", "T1499"]
        }
        return mitre_mapping.get(attack_type, [])
    
    def _persist_sequence(self, sequence: AttackSequence) -> None:
        """Save attack sequence to disk."""
        try:
            filename = self.replay_dir / f"{sequence.sequence_id}.json"
            with open(filename, 'w') as f:
                json.dump(sequence.to_dict(), f, indent=2)
        except Exception as e:
            print(f"Error persisting sequence: {e}")
    
    def get_active_attacks(self) -> List[AttackSequence]:
        """Get all active attack sequences."""
        with self.sequence_lock:
            return list(self.active_sequences.values())
    
    def get_attack_by_id(self, sequence_id: str) -> Optional[AttackSequence]:
        """Get specific attack sequence."""
        with self.sequence_lock:
            if sequence_id in self.active_sequences:
                return self.active_sequences[sequence_id]
            if sequence_id in self.completed_sequences:
                return self.completed_sequences[sequence_id]
        return None
    
    def replay_attack(self, sequence_id: str, speed_factor: float = 1.0) -> Dict:
        """Generate replay data for visualization/analysis."""
        sequence = self.get_attack_by_id(sequence_id)
        if not sequence:
            return {"error": "Sequence not found"}
        
        replay_data = {
            "sequence_id": sequence_id,
            "attack_name": sequence.attack_name,
            "total_events": len(sequence.events),
            "attack_duration": sequence.duration_seconds(),
            "events_timeline": [],
            "source_ips": sequence.source_ips,
            "targets": sequence.target_hosts,
            "severity": sequence.severity,
            "status": sequence.status
        }
        
        if sequence.events:
            start_time = datetime.fromisoformat(sequence.events[0].timestamp)
            
            for event in sequence.events:
                event_time = datetime.fromisoformat(event.timestamp)
                relative_time = (event_time - start_time).total_seconds() / speed_factor
                
                replay_data["events_timeline"].append({
                    "relative_time": relative_time,
                    "event": event.to_dict()
                })
        
        return replay_data
    
    def register_replay_listener(self, callback: Callable) -> None:
        """Register callback for replay events."""
        self.replay_listeners.append(callback)
    
    def _notify_replay_listeners(self, sequence: AttackSequence, event_type: str) -> None:
        """Notify listeners about replay events."""
        for listener in self.replay_listeners:
            try:
                listener({
                    "event_type": event_type,
                    "sequence": sequence.to_dict()
                })
            except Exception as e:
                print(f"Error notifying replay listener: {e}")
    
    def get_attack_statistics(self) -> Dict:
        """Get statistics about recorded attacks."""
        all_sequences = list(self.active_sequences.values()) + list(self.completed_sequences.values())
        
        if not all_sequences:
            return {"total_attacks": 0}
        
        attack_types = {}
        total_events = 0
        
        for sequence in all_sequences:
            attack_types[sequence.attack_type] = attack_types.get(sequence.attack_type, 0) + 1
            total_events += len(sequence.events)
        
        return {
            "total_attacks": len(all_sequences),
            "active_attacks": len(self.active_sequences),
            "concluded_attacks": len(self.completed_sequences),
            "total_events_recorded": total_events,
            "attack_types": attack_types,
            "avg_events_per_attack": total_events / len(all_sequences) if all_sequences else 0
        }


class AttackTimeline:
    """Generate attack timeline visualizations."""
    
    @staticmethod
    def generate_timeline(sequence: AttackSequence) -> Dict:
        """Generate timeline data for visualization."""
        timeline = {
            "sequence_id": sequence.sequence_id,
            "events": [],
            "start_time": sequence.start_time,
            "end_time": sequence.end_time or datetime.now().isoformat()
        }
        
        for event in sequence.events:
            timeline["events"].append({
                "timestamp": event.timestamp,
                "type": event.event_type,
                "source": event.source_ip,
                "destination": event.destination_ip,
                "severity": event.severity,
                "description": event.description
            })
        
        return timeline
