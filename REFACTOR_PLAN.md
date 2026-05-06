# xia SQL Refactor Plan

This document captures the next practical improvement plan for the Montoya-based refactor.

## Goal

Improve detection quality and operational usability without destabilizing the current plugin structure.

The plan follows the current architecture:

- `DetectionEngine` for scan orchestration
- `RequestMutation` and related mutators for request generation
- `XiaSqlPanel` for configuration and operator workflow

## Phase 1: ResponseComparator

### Objective

Replace the current coarse response-difference logic with a dedicated response comparison module.

### Why

The current logic is useful but still too rough in noisy real-world targets. A dedicated comparator should reduce false positives and produce more stable signals.

### Scope

- Extract comparison logic from `DetectionEngine`
- Keep response length as a fast signal
- Add head/tail comparison for large responses
- Add prefix/suffix trimming before comparison
- Reserve an interface for similarity strategies such as Levenshtein or Jaccard

### Expected outcome

- Lower false-positive rate
- Cleaner signal generation for future detection strategies
- Better separation between request generation and response analysis

## Phase 2: Hidden Parameter Fuzz

### Objective

Add support for fuzzing user-configured hidden parameters that are not already present in the original request.

### Why

This is valuable in real testing workflows, especially when parameter mining has already revealed candidate names.

### Scope

- Add a hidden-parameter list to plugin settings
- Generate additional requests by appending configured hidden parameters
- Support URL and form-style requests first
- Keep JSON hidden-parameter handling conservative in the first iteration
- Mark hidden-parameter attempts clearly in logs and UI

### Expected outcome

- Better coverage for parameter discovery scenarios
- Stronger integration with manual testing workflows

## Phase 3: Payload Groups

### Objective

Turn the current single custom SQL payload area into a grouped payload system.

### Why

Different parameter categories benefit from different payload sets. Grouping payloads will make the plugin easier to tune and easier to extend.

### Scope

- Add built-in groups such as:
  - `default`
  - `order`
  - `time`
  - `error`
  - `custom`
- Let parameter classification choose a default group automatically
- Allow operator selection of the active payload group in the UI
- Keep persistence support for group configuration

### Expected outcome

- Better targeted testing
- Cleaner payload management
- Easier future expansion for DBMS-specific or scenario-specific payload packs

## Recommended execution order

1. Implement `ResponseComparator`
2. Implement hidden-parameter fuzz
3. Implement payload groups

## Notes

- Keep edits aligned with current Montoya-based architecture
- Prefer incremental delivery over large rewrites
- Verify each phase with focused build and runtime checks before moving to the next
