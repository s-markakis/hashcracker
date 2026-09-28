"""Tests for output formatting."""
import json

from hashcracker.output import (
    format_results_json,
    format_results_csv,
    format_identification_json,
    format_identification_csv,
)


class TestJSONOutput:
    def test_crack_results_json(self):
        results = [
            {'hash': 'abc123', 'type': 'MD5', 'password': 'pass',
             'tool': 'hashcat', 'confidence': 0.95, 'time_elapsed': 1.5},
        ]
        output = format_results_json(results)
        parsed = json.loads(output)
        assert len(parsed) == 1
        assert parsed[0]['hash'] == 'abc123'
        assert parsed[0]['password'] == 'pass'
        assert parsed[0]['cracked'] is True

    def test_uncracked_result_json(self):
        results = [
            {'hash': 'abc123', 'type': 'MD5', 'password': None,
             'tool': '', 'confidence': 0.95, 'time_elapsed': None},
        ]
        output = format_results_json(results)
        parsed = json.loads(output)
        assert parsed[0]['cracked'] is False

    def test_identification_json(self):
        matches = [
            {'name': 'MD5', 'hashcat_mode': 0, 'john_format': 'Raw-MD5',
             'confidence': 0.95, 'note': None},
        ]
        output = format_identification_json('abc123', matches)
        parsed = json.loads(output)
        assert parsed['hash'] == 'abc123'
        assert parsed['matches'][0]['type'] == 'MD5'


class TestCSVOutput:
    def test_crack_results_csv(self):
        results = [
            {'hash': 'abc', 'type': 'MD5', 'password': 'pw',
             'tool': 'hashcat', 'confidence': 0.95, 'time_elapsed': 1.0},
        ]
        output = format_results_csv(results)
        lines = output.strip().split('\n')
        assert len(lines) == 2  # header + 1 row
        assert 'hash,type,password' in lines[0]

    def test_identification_csv(self):
        matches = [
            {'name': 'MD5', 'hashcat_mode': 0, 'john_format': 'Raw-MD5',
             'confidence': 0.95, 'note': None},
        ]
        output = format_identification_csv('abc', matches)
        lines = output.strip().split('\n')
        assert len(lines) == 2
        assert 'MD5' in lines[1]
