from flask import Flask


def localize(data: str | bool) -> str:
    data = str(data)
    return {
        "yes": "✅",
        "no": "❌",
        "active": "✅",
        "disabled": "❌",
        "true": "✅",
        "false": "❌",
    }.get(data.lower(), data)


def as_megabytes(data: str) -> str:
    try:
        mb = int(data) / 1048576
        return f"{mb:.0f}"
    except:
        return data


def register(app: Flask):
    app.jinja_env.filters["localize"] = localize
    app.jinja_env.filters["as_megabytes"] = as_megabytes
