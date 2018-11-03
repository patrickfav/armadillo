package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import androidx.annotation.Nullable;

public class MockSharedPref implements SharedPreferences {
    private final Map<String, Object> internalMap = new HashMap<>();
    private final Set<OnSharedPreferenceChangeListener> listeners = new HashSet<>();

    @Override
    public Map<String, ?> getAll() {
        return internalMap;
    }

    @Nullable
    @Override
    public String getString(String s, @Nullable String s1) {
        String result = (String) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return s1;
        }
    }

    @Nullable
    @Override
    public Set<String> getStringSet(String s, @Nullable Set<String> set) {
        Set<String> result = (Set) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return set;
        }
    }

    @Override
    public int getInt(String s, int i) {
        Integer result = (Integer) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return i;
        }
    }

    @Override
    public long getLong(String s, long l) {
        Long result = (Long) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return l;
        }
    }

    @Override
    public float getFloat(String s, float v) {
        Float result = (Float) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return v;
        }
    }

    @Override
    public boolean getBoolean(String s, boolean b) {
        Boolean result = (Boolean) internalMap.get(s);
        if (result != null) {
            return result;
        } else {
            return b;
        }
    }

    @Override
    public boolean contains(String s) {
        return internalMap.containsKey(s);
    }

    @Override
    public Editor edit() {
        return new Editor(this);
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        listeners.add(onSharedPreferenceChangeListener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        listeners.remove(onSharedPreferenceChangeListener);
    }

    void executeTransaction(Map<String, Object> putMap, List<String> removeList, boolean clear) {
        if (!clear) {
            for (Map.Entry<String, Object> stringObjectEntry : putMap.entrySet()) {
                this.internalMap.put(stringObjectEntry.getKey(), stringObjectEntry.getValue());
                informListeners(stringObjectEntry.getKey());
            }
            for (String s : removeList) {
                this.internalMap.remove(s);
                informListeners(s);
            }
        } else {
            this.internalMap.clear();
        }
    }

    private void informListeners(String key) {
        for (OnSharedPreferenceChangeListener listener : listeners) {
            listener.onSharedPreferenceChanged(this, key);
        }
    }

    public static final class Editor implements SharedPreferences.Editor {
        private final MockSharedPref mockSharedPref;

        private final Map<String, Object> putMap = new HashMap<>();
        private final List<String> removeList = new LinkedList<>();
        private boolean clear = false;

        Editor(MockSharedPref mockSharedPref) {
            this.mockSharedPref = mockSharedPref;
        }

        @Override
        public SharedPreferences.Editor putString(String s, @Nullable String s1) {
            putMap.put(s, s1);
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String s, @Nullable Set<String> set) {
            putMap.put(s, set);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String s, int i) {
            putMap.put(s, i);
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String s, long l) {
            putMap.put(s, l);
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String s, float v) {
            putMap.put(s, v);
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String s, boolean b) {
            putMap.put(s, b);
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String s) {
            removeList.add(s);
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            clear = true;
            return this;
        }

        @Override
        public boolean commit() {
            mockSharedPref.executeTransaction(putMap, removeList, clear);
            return true;
        }

        @Override
        public void apply() {
            commit();
        }
    }
}
