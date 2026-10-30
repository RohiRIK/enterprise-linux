"""Minimal JSON Schema (draft 2020-12 subset) validator, stdlib only.

Supported keywords: type, enum, const, properties, required,
additionalProperties (bool or schema), patternProperties, items, minItems,
maxItems, uniqueItems, minimum, maximum, minLength, maxLength, pattern,
oneOf, anyOf, $ref (local "#/$defs/..." only), default (ignored).

This exists so the shipped roles.schema.json is the single source of truth
without adding a third-party dependency. Unknown keywords are ignored, as in
the JSON Schema spec.
"""

from __future__ import annotations

import re

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def validate(instance, schema: dict) -> list[str]:
    """Return a list of error strings (empty when valid)."""
    errors: list[str] = []
    _validate(instance, schema, schema, "$", errors)
    return errors


def _resolve(root: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        raise ValueError(f"only local $ref supported: {ref}")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _validate(inst, schema, root, path, errors):
    if schema is True or schema == {}:
        return
    if schema is False:
        errors.append(f"{path}: not allowed")
        return
    if "$ref" in schema:
        _validate(inst, _resolve(root, schema["$ref"]), root, path, errors)

    t = schema.get("type")
    if t is not None:
        names = t if isinstance(t, list) else [t]
        if not any(_is_type(inst, n) for n in names):
            errors.append(f"{path}: expected {' or '.join(names)}, got {type(inst).__name__}")
            return

    if "enum" in schema and inst not in schema["enum"]:
        errors.append(f"{path}: {inst!r} not one of {schema['enum']}")
    if "const" in schema and inst != schema["const"]:
        errors.append(f"{path}: must be {schema['const']!r}")

    if isinstance(inst, str):
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], inst):
            errors.append(f"{path}: {inst!r} does not match {schema['pattern']}")

    if _is_type(inst, "number"):
        if "minimum" in schema and inst < schema["minimum"]:
            errors.append(f"{path}: {inst} < minimum {schema['minimum']}")
        if "maximum" in schema and inst > schema["maximum"]:
            errors.append(f"{path}: {inst} > maximum {schema['maximum']}")

    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen = []
            for item in inst:
                if item in seen:
                    errors.append(f"{path}: duplicate item {item!r}")
                seen.append(item)
        if "items" in schema:
            for i, item in enumerate(inst):
                _validate(item, schema["items"], root, f"{path}[{i}]", errors)

    if isinstance(inst, dict):
        for key in schema.get("required", []):
            if key not in inst:
                errors.append(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        pprops = schema.get("patternProperties", {})
        addl = schema.get("additionalProperties", True)
        for key, value in inst.items():
            sub = f"{path}.{key}"
            matched = False
            if key in props:
                matched = True
                _validate(value, props[key], root, sub, errors)
            for pat, psch in pprops.items():
                if re.search(pat, key):
                    matched = True
                    _validate(value, psch, root, sub, errors)
            if not matched:
                if addl is False:
                    errors.append(f"{path}: unexpected property {key!r}")
                elif isinstance(addl, dict):
                    _validate(value, addl, root, sub, errors)

    for kw in ("oneOf", "anyOf"):
        if kw in schema:
            ok = 0
            for option in schema[kw]:
                sub_errors: list[str] = []
                _validate(inst, option, root, path, sub_errors)
                if not sub_errors:
                    ok += 1
            if (kw == "oneOf" and ok != 1) or (kw == "anyOf" and ok == 0):
                errors.append(f"{path}: does not match {kw} alternatives")
