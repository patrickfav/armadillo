package at.favre.lib.securesharedpreferences;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;
import at.favre.lib.armadillo.Armadillo;
import at.favre.lib.armadillo.ArmadilloSharedPreferences;
import at.favre.lib.armadillo.SecureSharedPreferenceCryptoException;
import at.favre.lib.securesharedpreferences.databinding.ActivityMainBinding;

import static at.favre.lib.securesharedpreferences.Utils.hideKeyboard;
import static at.favre.lib.securesharedpreferences.Utils.showToast;

// TODO do expensive calls in a background thread
public class MainActivity extends AppCompatActivity {

    public static final String PREF_NAME = "myPrefs";
    public static final String SECRET = "a secret";

    private ActivityMainBinding binding;
    private ArmadilloSharedPreferences encryptedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = DataBindingUtil.setContentView(this, R.layout.activity_main);
    }

    public void onInitClicked(View view) {
        Armadillo.Builder builder = Armadillo.create(this, PREF_NAME)
                .encryptionFingerprint(this, SECRET)
                .supportVerifyPassword(true);
        if (binding.password.getText() != null && binding.password.getText().length() > 0) {
            char[] password = new char[binding.password.length()];
            binding.password.getText().getChars(0, binding.password.length(), password, 0);
            builder.password(password);
        }
        encryptedPreferences = builder.build();
        if (encryptedPreferences.isValidPassword()) {
            onArmadilloInitialised();
        } else {
            onWrongPassword();
        }
    }

    public void onGetClicked(View view) {
        hideKeyboard(this);
        if (encryptedPreferences == null) {
            binding.passwordLayout.setError("You have to init Armadillo first!");
            return;
        } else if (binding.key.getText() == null || binding.key.getText().toString().isEmpty()) {
            binding.keyLayout.setError("Enter key to retrieve value");
            return;
        }

        try {
            String value = encryptedPreferences.getString(binding.key.getText().toString(), null);
            if (value == null) {
                showToast(this, "No value found for this key");
                return;
            }
            binding.value.setText(value);
        } catch (SecureSharedPreferenceCryptoException ex) {
            showToast(this, "Error while decrypting data!");
        }
    }

    public void onSetClicked(View view) {
        hideKeyboard(this);
        if (encryptedPreferences == null) {
            binding.passwordLayout.setError("You have to init Armadillo first!");
            return;
        } else if (binding.key.getText() == null || binding.key.getText().toString().isEmpty()) {
            binding.keyLayout.setError("Enter key to set a value");
            return;
        } else if (binding.value.getText() == null || binding.value.getText().toString().isEmpty()) {
            binding.valueLayout.setError("Value is empty");
            return;
        }
        try {
            encryptedPreferences.edit().putString(binding.key.getText().toString(), binding.value.getText().toString()).apply();
            showToast(this, "Saved!");
        } catch (SecureSharedPreferenceCryptoException ex) {
            showToast(this, "Error while encrypting data!");
        }
    }

    public void onCloseArmadilloClicked(View view) {
        if (encryptedPreferences == null) {
            binding.passwordLayout.setError("You have to init Armadillo first!");
            return;
        }
        encryptedPreferences.close();
        onArmadilloClosed();
    }

    public void onChangePasswordClicked(View view) {
        startActivity(new Intent(this, ChangePasswordActivity.class));
    }

    private void onArmadilloInitialised() {
        hideKeyboard(this);
        binding.passwordLayout.setErrorEnabled(false);
        binding.btnInit.setEnabled(false);
        binding.key.setEnabled(true);
        binding.key.requestFocus();
        binding.key.setText("");
        binding.value.setEnabled(true);
        binding.value.setText("");
        binding.btnGet.setEnabled(true);
        binding.btnSet.setEnabled(true);
        binding.btnClosePreferences.setEnabled(true);
        binding.btnChangePassword.setEnabled(true);
    }

    private void onWrongPassword() {
        onArmadilloClosed();
        binding.passwordLayout.setError("Incorrect password!");
    }

    private void onArmadilloClosed() {
        binding.btnInit.setEnabled(true);
        binding.key.setEnabled(false);
        binding.key.setText("");
        binding.value.setEnabled(false);
        binding.value.setText("");
        binding.btnGet.setEnabled(false);
        binding.btnSet.setEnabled(false);
        binding.btnClosePreferences.setEnabled(false);
        binding.btnChangePassword.setEnabled(false);
        binding.password.requestFocus();
    }
}
