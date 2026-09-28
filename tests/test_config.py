"""Tests for configuration loading and round-tripping."""
import importlib

from hashcracker import config as config_module


def _fresh_config(tmp_path, monkeypatch):
    """Return a Config instance pointed at a temp config file."""
    cfg_file = tmp_path / 'config.ini'
    monkeypatch.setattr(config_module, 'CONFIG_DIR', str(tmp_path))
    monkeypatch.setattr(config_module, 'CONFIG_FILE', str(cfg_file))
    return config_module.Config()


def test_defaults(tmp_path, monkeypatch):
    cfg = _fresh_config(tmp_path, monkeypatch)
    assert cfg.timeout == 300
    assert cfg.default_tool == 'both'
    # Online lookup is opt-in by default.
    assert cfg.online_enabled is False


def test_getint_and_getboolean(tmp_path, monkeypatch):
    cfg = _fresh_config(tmp_path, monkeypatch)
    assert cfg.getint('general', 'timeout') == 300
    assert cfg.getboolean('hashcat', 'force_cpu') is False


def test_set_save_reload(tmp_path, monkeypatch):
    cfg = _fresh_config(tmp_path, monkeypatch)
    cfg.set('general', 'timeout', 42)
    cfg.set('online', 'enabled', 'true')
    cfg.save()

    reloaded = config_module.Config()
    assert reloaded.timeout == 42
    assert reloaded.online_enabled is True


def test_hashcat_extra_args_split(tmp_path, monkeypatch):
    cfg = _fresh_config(tmp_path, monkeypatch)
    cfg.set('hashcat', 'extra_args', '--foo --bar baz')
    assert cfg.hashcat_extra_args == ['--foo', '--bar', 'baz']


def test_config_module_imports_cleanly():
    importlib.reload(config_module)
