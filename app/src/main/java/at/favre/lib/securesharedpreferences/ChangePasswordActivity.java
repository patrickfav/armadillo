package at.favre.lib.securesharedpreferences;

import android.content.Intent;
import android.databinding.DataBindingUtil;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;

import at.favre.lib.armadillo.Armadillo;
import at.favre.lib.armadillo.ArmadilloSharedPreferences;
import at.favre.lib.armadillo.SecureSharedPreferenceCryptoException;
import at.favre.lib.securesharedpreferences.databinding.ActivityChangePasswordBinding;

import static at.favre.lib.securesharedpreferences.MainActivity.PREF_NAME;
import static at.favre.lib.securesharedpreferences.MainActivity.SECRET;
import static at.favre.lib.securesharedpreferences.Utils.showToast;

// TODO do expensive calls in a background thread
public class ChangePasswordActivity extends AppCompatActivity {

    private ActivityChangePasswordBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = DataBindingUtil.setContentView(this, R.layout.activity_change_password);
        getSupportActionBar().setTitle("Change Password");
    }

    public void onChangePasswordClicked(View view) {
        if (binding.currentPassword.getText() == null) {
            binding.currentPasswordLayout.setError("Enter current password");
            return;
        } else if (binding.newPassword.getText() == null) {
            binding.newPassword.setError("Enter new password");
            return;
        }

        // Get current pass
        char[] currentPassword = new char[binding.currentPassword.length()];
        binding.currentPassword.getText().getChars(0, binding.currentPassword.length(), currentPassword, 0);

        // Init Armadillo
        ArmadilloSharedPreferences armadillo = Armadillo.create(this, PREF_NAME)
                .encryptionFingerprint(this, SECRET)
                .password(currentPassword)
                .supportVerifyPassword(true)
                .build();
        if(!armadillo.isValidPassword()) {
            binding.currentPasswordLayout.setError("Incorrect password!");
            return;
        }

        // Get new pass
        char[] newPassword = new char[binding.newPassword.length()];
        binding.newPassword.getText().getChars(0, binding.newPassword.length(), newPassword, 0);

        // Change pass
        try {
            armadillo.changePassword(newPassword);
            showToast(this, "Password successfully changed!");
            openMainActivity();
        } catch (SecureSharedPreferenceCryptoException ex) {
            binding.currentPasswordLayout.setError("Incorrect password!");
        }
    }

    private void openMainActivity() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
    }
}
