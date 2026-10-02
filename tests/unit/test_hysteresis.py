import ast
from pathlib import Path


def step():
    node = next(n for n in ast.parse(Path('contracts/AdvisoryFuse.py').read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'transition')
    ns = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'transition', 'exec'), ns)
    return ns['transition']


def test_expired_first_clean_observation_cannot_clear_trip():
    current = {'latched': True, 'clean_at': 100, 'spec': {'ttl': 120}}
    result = step()(current, 'CLEAN', 220)
    assert result['latched'] and result['state'] == 'RECOVERY_PENDING'
    assert result['clean_at'] == 220


def test_sub_minimum_gap_cannot_clear_trip():
    current = {'latched': True, 'clean_at': 100, 'spec': {'ttl': 120}}
    result = step()(current, 'CLEAN', 159)
    assert result['latched'] and result['state'] == 'RECOVERY_PENDING'
