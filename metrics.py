def precision(tp, fp):

    if tp + fp == 0:
        return 0

    return tp / (tp + fp)


def recall(tp, fn):

    if tp + fn == 0:
        return 0

    return tp / (tp + fn)


def f1(tp, fp, fn):

    p = precision(tp, fp)

    r = recall(tp, fn)

    if p + r == 0:
        return 0

    return 2 * p * r / (p + r)


def false_positive_rate(fp, tn):

    if fp + tn == 0:
        return 0

    return fp / (fp + tn)


def recall_at_k(
    relevant,
    retrieved,
    k
):

    retrieved_k = retrieved[:k]

    hits = len(
        set(relevant)
        &
        set(retrieved_k)
    )

    if not relevant:
        return 0

    return hits / len(relevant)