package at.favre.lib.securesharedpreferences;

import android.app.Application;

import com.facebook.stetho.Stetho;

import timber.log.Timber;

import static timber.log.Timber.DebugTree;

public class MyApplication extends Application {

    public void onCreate() {
        super.onCreate();
        Timber.plant(new DebugTree());
        Stetho.initializeWithDefaults(this);
    }
}
