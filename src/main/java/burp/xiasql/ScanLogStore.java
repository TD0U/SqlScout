package burp.xiasql;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public final class ScanLogStore {
    public interface Listener {
        void logChanged();
    }

    private final AtomicInteger sequence = new AtomicInteger();
    private final List<ScanLogEntry> scans = new CopyOnWriteArrayList<>();
    private final List<ScanLogEntry> attempts = new CopyOnWriteArrayList<>();
    private final Set<String> fingerprints = java.util.Collections.synchronizedSet(new HashSet<>());
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public int nextId() {
        return sequence.getAndIncrement();
    }

    public boolean rememberFingerprint(String fingerprint) {
        return fingerprints.add(fingerprint);
    }

    public void addScan(ScanLogEntry entry) {
        scans.add(entry);
        notifyListeners();
    }

    public void addAttempt(ScanLogEntry entry) {
        attempts.add(entry);
        notifyListeners();
    }

    public void replaceScan(ScanLogEntry entry) {
        for (int i = 0; i < scans.size(); i++) {
            if (scans.get(i).id() == entry.id()) {
                scans.set(i, entry);
                notifyListeners();
                return;
            }
        }
    }

    public void update() {
        notifyListeners();
    }

    public List<ScanLogEntry> scans() {
        return new ArrayList<>(scans);
    }

    public List<ScanLogEntry> attemptsFor(String fingerprint) {
        List<ScanLogEntry> matches = new ArrayList<>();
        for (ScanLogEntry entry : attempts) {
            if (entry.fingerprint().equals(fingerprint)) {
                matches.add(entry);
            }
        }
        return matches;
    }

    public void clear() {
        sequence.set(0);
        scans.clear();
        attempts.clear();
        fingerprints.clear();
        notifyListeners();
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    private void notifyListeners() {
        for (Listener listener : listeners) {
            listener.logChanged();
        }
    }
}
