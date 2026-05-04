import math

def human_size(n: int) -> str:
    if n is None or n == "":
        return ""
    if n == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(n, 1024)))
    i = min(i, len(units) - 1)
    p = math.pow(1024, i)
    s = round(n / p, 2)
    return f"{s} {units[i]}"