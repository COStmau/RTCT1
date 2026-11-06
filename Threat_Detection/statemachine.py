"""State-machine anomaly detection after Cao, Blaise, Verwer and Rebecchi (ARES 2022).

This module used to hold the whole method in 789 lines and 50 public names. It is now a
thin re-export of three modules, kept so every existing caller and test keeps working:

  methods.pdfa    learning -- flows, symbols, the prefix tree, ALERGIA, the PDFA
  methods.scores  scoring  -- trace likelihood, and SEQUENT's frequency scores
  methods.sweep   the experiment -- one flag_stats row per stratum

New code should import from those directly. This file exists only for the names.

Run the sweep with:  .venv/bin/python statemachine.py
                     .venv/bin/python -m methods.sweep      (the same thing)
"""
from methods.pdfa import (ALERGIA_ALPHA, FLAG_COLUMNS, FLOW_COLUMNS, MISSING_PROB, NBINS,
                          PDFA, TRACE_LEN, _Node, _attempt, _bin, _compatible, _copy_tree,
                          _encode_value, _flag_bits, _fold_into, _frequency_tests,
                          _hoeffding, _step, encode, fit_frequency, fit_model, fit_percentile,
                          fit_segments, learn_pdfa, load_flow_packets, make_flows,
                          make_traces, segment_flows, split_flows)
from methods.scores import (FORGET_SECONDS, PAIR_CSV, TRAIN_COUNTS, FrequencyScorer,
                            WindowedFrequencyScorer, flags_for_windows, frequency_cutoff,
                            frequency_scores_by_window, n_windows_for, pdfa_states_in_order,
                            plot_pdfa, score_cutoff, score_flows, score_pair,
                            state_train_counts, statemachine_rows, trace_score, trace_states,
                            write_pair)
from methods.sweep import SWEEP_CSV, main

# Re-exported because the original module imported it: callers and tests read it here.
from detectors import BENIGN_QUANTILE  # noqa: E402,F401

if __name__ == "__main__":
    main()
