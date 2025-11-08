#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np

# =========================
# 1) Corpus d'entraînement
# =========================

docs = [
    "ce film est bien",          # +1
    "j adore ce film",           # +1
    "ce film est incroyable",    # +1
    "bon et genial",             # +1
    "ce film est nul",           # -1
    "je deteste ce film",        # -1
    "le film est affreux",       # -1
    "mauvais et horrible",       # -1
]

y = [1, 1, 1, 1, 0, 0, 0, 0]     # 1 = positif, 0 = negatif

# IMPORTANT : token_pattern pour garder les mots d'une lettre (j)
vect = CountVectorizer(
    lowercase=True,
    token_pattern=r"(?u)\b\w+\b"
)

X = vect.fit_transform(docs)
vocab = vect.get_feature_names_out()
print("Vocabulaire (|V| = {}):".format(len(vocab)))
print(vocab, "\n")

# =========================
# 2) Comptages par classe
# =========================

# somme des occurrences par classe
X_pos = X[np.array(y) == 1]
X_neg = X[np.array(y) == 0]

counts_pos = np.asarray(X_pos.sum(axis=0)).ravel()
counts_neg = np.asarray(X_neg.sum(axis=0)).ravel()

print("Comptages par mot (N_w,+) et (N_w,-):")
for w, c_pos, c_neg in zip(vocab, counts_pos, counts_neg):
    print(f"{w:10s}  Nw,+ = {c_pos:2d}   Nw,- = {c_neg:2d}")
print()

print("Total mots positifs :", counts_pos.sum())
print("Total mots négatifs :", counts_neg.sum(), "\n")

# =========================
# 3) Modèle Naive Bayes
# =========================

clf = MultinomialNB(alpha=1.0)   # Laplace = 1
clf.fit(X, y)

print("Priors de classe (P(c)) :")
print("log P(c)  :", clf.class_log_prior_)
print("P(c)      :", np.exp(clf.class_log_prior_), "\n")

# feature_log_prob_ : log P(w | c)
feat_log_prob = clf.feature_log_prob_
feat_prob = np.exp(feat_log_prob)

print("Probabilités P(w | classe) avec Laplace :")
print("mot       P(w|neg)   P(w|pos)")
for i, w in enumerate(vocab):
    p_neg = feat_prob[0, i]   # classe 0 = négatif
    p_pos = feat_prob[1, i]   # classe 1 = positif
    print(f"{w:10s}  {p_neg:7.4f}   {p_pos:7.4f}")
print()

# =========================
# 4) Tests des deux phrases
# =========================

test_docs = [
    "ce film est mauvais",
    "ce film est mauvais bien et genial"
]

X_test = vect.transform(test_docs)
probas = clf.predict_proba(X_test)
preds = clf.predict(X_test)

for doc, p, yhat in zip(test_docs, probas, preds):
    label = "positif" if yhat == 1 else "negatif"
    print(f"Phrase : « {doc} »")
    print(f"  P(negatif) = {p[0]:.4f}")
    print(f"  P(positif) = {p[1]:.4f}")
    print(f"  → prédiction sklearn : {label}")
    print()
