package at.favre.lib.securepref;

import android.content.SharedPreferences;
import android.support.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class MockSharedPref implements SharedPreferences {
    private Map<String, Object> internalMap = new HashMap<>();

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
        return new Editor(internalMap, this);
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        throw new UnsupportedOperationException("listener not supported");
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        throw new UnsupportedOperationException("listener not supported");
    }

    void setInternalMap(Map<String, Object> map) {
        this.internalMap = map;
    }

    public static final class Editor implements SharedPreferences.Editor {
        private final Map<String, Object> cache;
        private final MockSharedPref mockSharedPref;

        public Editor(Map<String, Object> original, MockSharedPref mockSharedPref) {
            this.cache = new HashMap<>(original);
            this.mockSharedPref = mockSharedPref;
        }

        @Override
        public SharedPreferences.Editor putString(String s, @Nullable String s1) {
            cache.put(s, s1);
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String s, @Nullable Set<String> set) {
            cache.put(s, set);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String s, int i) {
            cache.put(s, i);
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String s, long l) {
            cache.put(s, l);
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String s, float v) {
            cache.put(s, v);
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String s, boolean b) {
            cache.put(s, b);
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String s) {
            cache.remove(s);
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            cache.clear();
            return this;
        }

        @Override
        public boolean commit() {
            mockSharedPref.setInternalMap(cache);
            return true;
        }

        @Override
        public void apply() {
            commit();
        }
    }
}
