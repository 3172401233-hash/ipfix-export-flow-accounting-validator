"""Unit tests for the IPFIX flow accounting validator.

All records used here are local synthetic samples.
"""

import unittest

from ipfix_validator import (
    DataRecord,
    FlowAccountingValidator,
    Template,
    effective_sampling_rate,
)

FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port",
          "bytes", "packets", "flow_start", "flow_end")


def make_record(template_id=256, template_version=1, byte_count=1000,
                packet_count=10, sampling_rate=1, flow_start=0.0,
                flow_end=10.0, exported_at=10.0, pre_scaled=False,
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=12345, dst_port=80):
    return DataRecord(
        template_id=template_id,
        template_version=template_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        byte_count=byte_count,
        packet_count=packet_count,
        sampling_rate=sampling_rate,
        flow_start=flow_start,
        flow_end=flow_end,
        exported_at=exported_at,
        pre_scaled=pre_scaled,
    )


class TemplateRedefinitionTest(unittest.TestCase):
    def test_redefinition_withdraws_old_version(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        validator.add_template(Template(256, 2, FIELDS, defined_at=100.0))

        self.assertEqual(len(validator.report.template_issues), 1)
        self.assertIn("redefined", validator.report.template_issues[0])

        # Old record exported before redefinition still matches version 1.
        old = make_record(template_version=1, exported_at=50.0)
        # New record exported after redefinition must use version 2.
        new = make_record(template_version=2, exported_at=150.0,
                          flow_start=100.0, flow_end=110.0)
        report = validator.process_records([old, new])
        self.assertEqual(report.template_issues, validator.report.template_issues[:1])
        self.assertEqual(report.total_true_bytes, 2000)

    def test_version_mismatch_record_rejected(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 2, FIELDS, defined_at=0.0))
        stale = make_record(template_version=1, exported_at=10.0)
        report = validator.process_records([stale])
        self.assertEqual(len(report.template_issues), 1)
        self.assertIn("does not match", report.template_issues[0])
        self.assertEqual(report.total_true_bytes, 0)

    def test_record_after_withdrawal_is_unattributable(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        validator.withdraw_template(256, 1, at=100.0)
        late = make_record(template_version=1, exported_at=150.0)
        report = validator.process_records([late])
        self.assertEqual(len(report.unattributable_records), 1)
        self.assertEqual(report.total_true_bytes, 0)


class SamplingChangeTest(unittest.TestCase):
    def test_sampling_rate_change_across_redefinition(self):
        validator = FlowAccountingValidator()
        validator.add_template(
            Template(256, 1, FIELDS, sampling_rate=100, defined_at=0.0))
        validator.add_template(
            Template(256, 2, FIELDS, sampling_rate=1000, defined_at=100.0))

        # Records carry rate 1 and inherit the template rate of their epoch.
        before = make_record(template_version=1, sampling_rate=1,
                             byte_count=10, exported_at=50.0)
        after = make_record(template_version=2, sampling_rate=1,
                            byte_count=10, flow_start=100.0, flow_end=110.0,
                            exported_at=150.0)
        report = validator.process_records([before, after])
        self.assertEqual(report.total_true_bytes, 10 * 100 + 10 * 1000)

    def test_no_double_amplification(self):
        template = Template(256, 1, FIELDS, sampling_rate=100, defined_at=0.0)
        # Record already carries the same rate: apply once, not twice.
        rec = make_record(sampling_rate=100, byte_count=10)
        self.assertEqual(effective_sampling_rate(rec, template), 100)
        # Pre-scaled record must not be amplified again.
        pre = make_record(sampling_rate=100, byte_count=10, pre_scaled=True)
        self.assertEqual(effective_sampling_rate(pre, template), 1)
        # Rate-1 record inherits the template rate.
        plain = make_record(sampling_rate=1, byte_count=10)
        self.assertEqual(effective_sampling_rate(plain, template), 100)


class LongFlowSegmentationTest(unittest.TestCase):
    def test_segments_merge_without_overlap(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        segments = [
            make_record(byte_count=1000, flow_start=0.0, flow_end=60.0,
                        exported_at=60.0),
            make_record(byte_count=2000, flow_start=60.0, flow_end=120.0,
                        exported_at=120.0),
            make_record(byte_count=500, flow_start=120.0, flow_end=130.0,
                        exported_at=130.0),
        ]
        report = validator.process_records(segments)
        flow = report.flows[segments[0].flow_key]
        self.assertEqual(flow.segments, 3)
        self.assertEqual(flow.true_bytes, 3500)
        self.assertEqual(flow.merged_start, 0.0)
        self.assertEqual(flow.merged_end, 130.0)
        self.assertEqual(report.duplicate_billing, [])

    def test_overlapping_segments_counted_once(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        first = make_record(byte_count=1000, flow_start=0.0, flow_end=60.0,
                            exported_at=60.0)
        overlap = make_record(byte_count=900, flow_start=30.0, flow_end=90.0,
                              exported_at=90.0)
        report = validator.process_records([first, overlap])
        flow = report.flows[first.flow_key]
        self.assertEqual(flow.true_bytes, 1000)
        self.assertEqual(len(report.duplicate_billing), 1)
        self.assertIn("overlapping", report.duplicate_billing[0])

    def test_exact_duplicate_export_skipped(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        rec = make_record(byte_count=1000)
        dup = make_record(byte_count=1000)
        report = validator.process_records([rec, dup])
        self.assertEqual(report.total_true_bytes, 1000)
        self.assertEqual(len(report.duplicate_billing), 1)
        self.assertIn("duplicate export", report.duplicate_billing[0])


class OutOfOrderExportTest(unittest.TestCase):
    def test_out_of_order_segments_merge_correctly(self):
        validator = FlowAccountingValidator()
        validator.add_template(Template(256, 1, FIELDS, defined_at=0.0))
        # Exported out of order: later segment arrives first.
        late = make_record(byte_count=500, flow_start=120.0, flow_end=130.0,
                           exported_at=130.0)
        middle = make_record(byte_count=2000, flow_start=60.0, flow_end=120.0,
                             exported_at=120.0)
        early = make_record(byte_count=1000, flow_start=0.0, flow_end=60.0,
                            exported_at=60.0)
        report = validator.process_records([late, early, middle])
        flow = report.flows[early.flow_key]
        self.assertEqual(flow.segments, 3)
        self.assertEqual(flow.true_bytes, 3500)
        self.assertEqual(report.duplicate_billing, [])


class TrafficDifferenceTest(unittest.TestCase):
    def test_difference_against_interface_counter(self):
        validator = FlowAccountingValidator()
        validator.add_template(
            Template(256, 1, FIELDS, sampling_rate=100, defined_at=0.0))
        rec = make_record(sampling_rate=1, byte_count=10, packet_count=1)
        report = validator.process_records([rec], interface_bytes=1200)
        self.assertEqual(report.total_true_bytes, 1000)
        self.assertEqual(report.traffic_difference, 200)


if __name__ == "__main__":
    unittest.main()
