from datetime import timedelta


try:
    import humanize  # type: ignore
except Exception as e:
    print(e)
    humanize = None


def naturaldelta(td: timedelta) -> str:
    return humanize.naturaldelta(td) if humanize else str(td)


__all__ = ["humanize"]
