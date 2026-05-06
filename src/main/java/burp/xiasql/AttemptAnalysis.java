package burp.xiasql;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public final class AttemptAnalysis {
    private final String changeSummary;
    private final Set<AttemptSignal> signals;
    private final FindingVerdict verdict;
    private final double similarity;

    public AttemptAnalysis(String changeSummary, Set<AttemptSignal> signals, FindingVerdict verdict, double similarity) {
        this.changeSummary = changeSummary;
        this.signals = signals.isEmpty() ? Collections.emptySet() : Collections.unmodifiableSet(EnumSet.copyOf(signals));
        this.verdict = verdict;
        this.similarity = similarity;
    }

    public String changeSummary() {
        return changeSummary;
    }

    public Set<AttemptSignal> signals() {
        return signals;
    }

    public FindingVerdict verdict() {
        return verdict;
    }

    public double similarity() {
        return similarity;
    }
}
