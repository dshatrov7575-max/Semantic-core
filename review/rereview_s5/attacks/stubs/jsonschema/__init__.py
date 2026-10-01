# stub for running core/validator.py text functions under interpreters without jsonschema (no network); schema checks unused here
class FormatChecker:
    def __init__(self, *a, **k): pass
    def checks(self, *a, **k):
        return lambda f: f
class Draft202012Validator:
    def __init__(self, *a, **k): pass
