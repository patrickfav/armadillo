package at.favre.lib.securesharedpreferences;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import at.favre.lib.armadillo.Armadillo;

public class MainActivity extends AppCompatActivity {

    private SharedPreferences encryptedPreferences;

    private EditText editTextKey;
    private EditText editTextValue;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        encryptedPreferences = Armadillo.create(this, "myPrefs")
                .encryptionFingerprint(this, "a secret")
                .password("pass".toCharArray())
                .build();
        editTextKey = findViewById(R.id.et_key);
        editTextValue = findViewById(R.id.et_value);

        findViewById(R.id.btn_get).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (editTextKey.getText() == null || editTextKey.getText().toString().isEmpty()) {
                    Toast.makeText(MainActivity.this, "Fill key textfield to retrieve value", Toast.LENGTH_SHORT).show();
                    return;
                }

                String value = encryptedPreferences.getString(editTextKey.getText().toString(), null);

                if (value == null) {
                    Toast.makeText(MainActivity.this, "No value found for this key", Toast.LENGTH_SHORT).show();
                    return;
                }

                editTextValue.setText(value);
            }
        });

        findViewById(R.id.btn_set).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (editTextKey.getText() == null || editTextKey.getText().toString().isEmpty() ||
                        editTextValue.getText() == null || editTextValue.getText().toString().isEmpty()) {
                    Toast.makeText(MainActivity.this, "Fill key and value textfield first", Toast.LENGTH_SHORT).show();
                    return;
                }

                encryptedPreferences.edit().putString(editTextKey.getText().toString(), editTextValue.getText().toString()).apply();
                Toast.makeText(MainActivity.this, "Saved.", Toast.LENGTH_SHORT).show();
            }
        });
    }
}
