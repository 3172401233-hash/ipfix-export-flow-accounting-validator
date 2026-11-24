"""IPFIX flow accounting validator.

Rebuilds true per-flow usage from templates, sampling rates and record
timestamps, then reports traffic differences, template problems,
duplicate billing and unattributable records.

Compatible with Python 3.8.2.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Template:
    """IPFIX template definition and its lifecycle."""

    template_id: int
    version: int
    fields: Tuple[str, ...]
    sampling_rate: int = 1
    defined_at: float = 0.0
    withdrawn_at: Optional[float] = None

    def active_at(self, timestamp: float) -> bool:
        if timestamp < self.defined_at:
            return False
        if self.withdrawn_at is not None and timestamp >= self.withdrawn_at:
            return False
        return True


@dataclass
class DataRecord:
    """A single IPFIX Data Record."""

    template_id: int
    template_version: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    byte_count: int
    packet_count: int
    sampling_rate: int
    flow_start: float
    flow_end: float
    exported_at: float = 0.0
    # True if the exporter already scaled counters by the sampling rate.
    pre_scaled: bool = False

    @property
    def flow_key(self) -> Tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    @property
    def signature(self) -> Tuple:
        """Identifies an exact duplicate export of the same record."""
        return (
            self.flow_key,
            self.flow_start,
            self.flow_end,
            self.byte_count,
            self.packet_count,
            self.template_id,
            self.template_version,
        )


@dataclass
class FlowUsage:
    """Merged true usage of one flow."""

    flow_key: Tuple
    true_bytes: int = 0
    true_packets: int = 0
    segments: int = 0
    merged_start: float = 0.0
    merged_end: float = 0.0


@dataclass
class ValidationReport:
    total_true_bytes: int = 0
    total_true_packets: int = 0
    interface_bytes: int = 0
    traffic_difference: int = 0
    template_issues: List[str] = field(default_factory=list)
    duplicate_billing: List[str] = field(default_factory=list)
    unattributable_records: List[str] = field(default_factory=list)
    flows: Dict[Tuple, FlowUsage] = field(default_factory=dict)


class TemplateRegistry:
    """Keeps template definition history per ID and checks lifecycles."""

    def __init__(self) -> None:
        self._history: Dict[int, List[Template]] = {}

    def define(self, template: Template) -> Optional[str]:
        """Register a template; redefining an ID withdraws the old version."""
        history = self._history.setdefault(template.template_id, [])
        issue = None
        for old in history:
            if old.withdrawn_at is None:
                old.withdrawn_at = template.defined_at
                issue = (
                    "template %d redefined at %.3f: version %d -> %d"
                    % (template.template_id, template.defined_at,
                       old.version, template.version)
                )
        history.append(template)
        return issue

    def withdraw(self, template_id: int, version: int, at: float) -> Optional[str]:
        for tpl in self._history.get(template_id, []):
            if tpl.version == version and tpl.withdrawn_at is None:
                tpl.withdrawn_at = at
                return None
        return "withdraw of unknown template %d version %d" % (template_id, version)

    def lookup(self, template_id: int, exported_at: float) -> Optional[Template]:
        for tpl in self._history.get(template_id, []):
            if tpl.active_at(exported_at):
                return tpl
        return None


def effective_sampling_rate(record: DataRecord, template: Template) -> int:
    """Sampling rate to apply, avoiding double amplification.

    The record's own rate wins; a pre-scaled record is never scaled again;
    a record with rate 1 falls back to the template rate exactly once.
    """
    rate = record.sampling_rate or 1
    if record.pre_scaled:
        return 1
    if rate == 1 and template.sampling_rate > 1:
        return template.sampling_rate
    return rate


class FlowAccountingValidator:
    def __init__(self) -> None:
        self.registry = TemplateRegistry()
        self.report = ValidationReport()

    def add_template(self, template: Template) -> None:
        issue = self.registry.define(template)
        if issue:
            self.report.template_issues.append(issue)

    def withdraw_template(self, template_id: int, version: int, at: float) -> None:
        issue = self.registry.withdraw(template_id, version, at)
        if issue:
            self.report.template_issues.append(issue)

    def process_records(self, records: List[DataRecord],
                        interface_bytes: int = 0) -> ValidationReport:
        self.report.interface_bytes = interface_bytes

        attributable: List[Tuple[DataRecord, int]] = []
        for rec in records:
            template = self.registry.lookup(rec.template_id, rec.exported_at)
            if template is None:
                self.report.unattributable_records.append(
                    "no active template %d at export time %.3f for flow %s"
                    % (rec.template_id, rec.exported_at, rec.flow_key)
                )
                continue
            if rec.template_version != template.version:
                self.report.template_issues.append(
                    "record version %d does not match active template %d "
                    "version %d for flow %s"
                    % (rec.template_version, rec.template_id,
                       template.version, rec.flow_key)
                )
                continue
            rate = effective_sampling_rate(rec, template)
            attributable.append((rec, rate))

        self._merge_flows(attributable)

        self.report.total_true_bytes = sum(
            f.true_bytes for f in self.report.flows.values())
        self.report.total_true_packets = sum(
            f.true_packets for f in self.report.flows.values())
        self.report.traffic_difference = (
            interface_bytes - self.report.total_true_bytes)
        return self.report

    def _merge_flows(self, attributable: List[Tuple[DataRecord, int]]) -> None:
        """Merge segments per flow; handle reordering, duplicates, overlap."""
        by_flow: Dict[Tuple, List[Tuple[DataRecord, int]]] = {}
        for rec, rate in attributable:
            by_flow.setdefault(rec.flow_key, []).append((rec, rate))

        for flow_key, segments in by_flow.items():
            # Out-of-order export: sort by start time before merging.
            segments.sort(key=lambda item: (item[0].flow_start, item[0].flow_end))
            usage = FlowUsage(flow_key=flow_key)
            seen_signatures = set()
            covered_end: Optional[float] = None

            for rec, rate in segments:
                if rec.signature in seen_signatures:
                    self.report.duplicate_billing.append(
                        "duplicate export of flow %s interval [%.3f, %.3f] "
                        "bytes=%d skipped"
                        % (flow_key, rec.flow_start, rec.flow_end,
                           rec.byte_count)
                    )
                    continue
                seen_signatures.add(rec.signature)

                if covered_end is not None and rec.flow_start < covered_end:
                    # Overlapping long-flow segments must not be billed twice.
                    self.report.duplicate_billing.append(
                        "overlapping segment of flow %s interval [%.3f, %.3f] "
                        "overlaps covered end %.3f; segment skipped"
                        % (flow_key, rec.flow_start, rec.flow_end, covered_end)
                    )
                    continue

                usage.true_bytes += rec.byte_count * rate
                usage.true_packets += rec.packet_count * rate
                usage.segments += 1
                if usage.segments == 1:
                    usage.merged_start = rec.flow_start
                usage.merged_end = max(usage.merged_end, rec.flow_end)
                covered_end = max(covered_end or rec.flow_end, rec.flow_end)

            self.report.flows[flow_key] = usage
