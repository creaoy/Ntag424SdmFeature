package de.androidcrypto.ntag424sdmfeature;

import static net.bplearning.ntag424.CommandResult.PERMISSION_DENIED;
import static net.bplearning.ntag424.constants.Ntag424.CC_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Ntag424.NDEF_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_EVERYONE;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY0;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY1;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY2;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY3;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY4;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_NONE;

import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_1;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_2;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_3;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_4;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_DEFAULT;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_VERSION_DEFAULT;
import static de.androidcrypto.ntag424sdmfeature.Constants.MASTER_APPLICATION_KEY;
import static de.androidcrypto.ntag424sdmfeature.Constants.MASTER_APPLICATION_KEY_FOR_DIVERSIFYING;
import static de.androidcrypto.ntag424sdmfeature.Constants.NDEF_FILE_01_CAPABILITY_CONTAINER_DEFAULT;
import static de.androidcrypto.ntag424sdmfeature.Constants.SYSTEM_IDENTIFIER_FOR_DIVERSIFYING;
import static de.androidcrypto.ntag424sdmfeature.Constants.URL_DOMAIN_TEMPLATE;
import static de.androidcrypto.ntag424sdmfeature.Constants.URL_DOMAIN_TEMPLATE_LEN;
import static de.androidcrypto.ntag424sdmfeature.Constants.SALT_FOR_DIVERSIFYING;
import static de.androidcrypto.ntag424sdmfeature.Constants.APPLICATION_KEY_ETH_DIVERSIFYING;


import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.RadioButton;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.card.KeyInfo;
import net.bplearning.ntag424.command.ChangeFileSettings;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.command.WriteData;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.exception.ProtocolException;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;
import net.bplearning.ntag424.command.ChangeKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class EncryptedFileSunCustomKeysActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = EncryptedFileSunCustomKeysActivity.class.getSimpleName();
    private com.google.android.material.textfield.TextInputEditText output;
    private RadioButton rbUid, rbCounter, rbUidCounter;
    private DnaCommunicator dnaC = new DnaCommunicator();
    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_encrypted_file_sun_custom_keys);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        rbUid = findViewById(R.id.rbFieldUid);
        rbCounter = findViewById(R.id.rbFieldCounter);
        rbUidCounter = findViewById(R.id.rbFieldUidCounter);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * NFC tag handling section
     * These methods are running in another thread when a card is discovered and
     * cannot direct interact with the UI Thread.
     * Use `runOnUiThread` method to change the UI from these methods
     */

    @Override
    public void onTagDiscovered(Tag tag) {

        writeToUiAppend(output, "NFC tag discovered");

        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                });

                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppend(output, "Could not connect to the tag, aborted");
                    isoDep.close();
                    return;
                }

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend(output, "Tag ID: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppend(output, "NFC tag connected");

                runWorker();
            }

        } catch (IOException e) {
            writeToUiAppend(output, "ERROR: IOException " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppend(output, "ERROR: Exception " + e.getMessage());
            e.printStackTrace();
        }

    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for NFC A card type and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is set
            // so the reader won't try to get a NDEF message
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null) {
            mNfcAdapter.disableReaderMode(this);
        }
    }

    private void runWorker() {
        Log.d(TAG, "Encrypted File SUN Custom Keys Activity Worker");
        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {

                unsetActivty();

                boolean success = false;
                try {
                    dnaC = new DnaCommunicator();
                    try {
                        dnaC.setTransceiver((bytesToSend) -> isoDep.transceive(bytesToSend));
                    } catch (NullPointerException npe) {
                        writeToUiAppend(output, "Please tap a tag before running any tests, aborted");
                        return;
                    }
                    dnaC.setLogger((info) -> Log.d(TAG, "Communicator: " + info));
                    dnaC.beginCommunication();


                    // Check if the tag is already personalized
                    boolean isPersonalized = checkIfPersonalized();
                    byte[] auth_key = MASTER_APPLICATION_KEY;

                    if (!isPersonalized) {
                        // Personalize the tag
                        personalizeTag();
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);

                        if (!success) {
                            throw new Exception("Authentication with Master Application Key failed");
                        }
                        writeToUiAppend(output, "Authentication with Master Application Key successful");

                    } else {
                        writeToUiAppend(output, "Tag is already personalized. Skipping personalization step.");
                    }



                    /**
                     * These steps are running - assuming that all keys are 'default' keys filled with 16 00h values
                     * 1) Authenticate with Application Key 00h in AES mode
                     * 2) If the authentication in AES mode fails try to authenticate in LRP mode
                     * 3) Write an URL template to file 02 with PICC (Uid and/or Counter) plus CMAC
                     * 4) Get existing file settings for file 02
                     * 5) Save the modified file settings back to the tag
                     */


                } catch (IOException e) {
                    Log.e(TAG, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                } catch (Exception e) {
                    Log.e(TAG, "General Exception: " + e.getMessage());
                    writeToUiAppend(output, "General Exception: " + e.getMessage());
                }
                writeToUiAppend(output, "== SETUP FINISHED ==");
                vibrateShort();
            }
        });
        worker.start();
    }

    private boolean checkIfPersonalized() {
        // Try to authenticate with the custom master key
        try {
            return AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, MASTER_APPLICATION_KEY);
        } catch (IOException e) {
            Log.e(TAG, "Exception: " + e.getMessage());
//            throw new RuntimeException(e);
        }
        return false;
    }

    private void personalizeTag() throws Exception {
        // Step 1: Try to authenticate with either the DEFAULT or CUSTOM appKey 0 (Master Application Key)
        boolean success = authenticateWithMasterKey();
        if (!success) {
            throw new Exception("Authentication with Master Application Key failed. Unable to proceed.");
        }
        writeToUiAppend(output, "Authentication with Master Application Key successful");


        // Step 2: Change appKeys 1, 2, 3 and 4 to CUSTOM keys
        changeKey(ACCESS_KEY1, APPLICATION_KEY_1);
        changeKey(ACCESS_KEY2, APPLICATION_KEY_2);
        changeKey(ACCESS_KEY3, APPLICATION_KEY_3);
        changeKey(ACCESS_KEY4, APPLICATION_KEY_4);

        // Step 3: Change appKey 0 to CUSTOM key if it's not already
        changeKey(ACCESS_KEY0, MASTER_APPLICATION_KEY);

        // Step 1: Try to authenticate with either the DEFAULT or CUSTOM appKey 0 (Master Application Key)
        success = authenticateWithMasterKey();
        if (!success) {
            throw new Exception("Authentication with Master Application Key failed. Unable to proceed.");
        }
        writeToUiAppend(output, "Authentication with Master Application Key successful");


        // Step 4: Get current file settings
        writeToUiAppend(output, "Retrieving current file settings...");
        FileSettings fileSettings = GetFileSettings.run(dnaC, NDEF_FILE_NUMBER);
        writeToUiAppend(output, "Current file settings retrieved");

        // Step 5: Set up SDM settings
        SDMSettings sdmSettings = new SDMSettings();
        sdmSettings.sdmEnabled = true;
        writeToUiAppend(output, "SDM enabled");

        sdmSettings.sdmMetaReadPerm = ACCESS_KEY3;
        sdmSettings.sdmFileReadPerm = ACCESS_KEY4;
        sdmSettings.sdmReadCounterRetrievalPerm = ACCESS_NONE;
        sdmSettings.sdmOptionEncryptFileData = true;
        sdmSettings.sdmOptionUid = true;
        writeToUiAppend(output, "UID mirroring option enabled");
        sdmSettings.sdmOptionReadCounter = true;
        fileSettings.sdmSettings = sdmSettings;

        // Step 7: Setup URL and write data
        boolean isLrpAuthenticationMode = false; // Set this based on your authentication mode
        setupUrlAndWriteData(sdmSettings, isLrpAuthenticationMode);

        // Step 6: Set other file permissions
        writeToUiAppend(output, "Setting file permissions...");
        fileSettings.readPerm = ACCESS_KEY2;
        fileSettings.writePerm = ACCESS_KEY2;
        fileSettings.readWritePerm = ACCESS_KEY2;
        fileSettings.changePerm = ACCESS_KEY0;

        // Apply the final file settings
        writeToUiAppend(output, "Applying final file settings...");
        ChangeFileSettings.run(dnaC, NDEF_FILE_NUMBER, fileSettings);

        writeToUiAppend(output, "Tag personalization completed successfully");
    }

    private void setupUrlAndWriteData(SDMSettings sdmSettings, boolean isLrpAuthenticationMode) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        writeToUiAppend(output, "Setting up URL and writing data...");

        // Create NDEF record with URL template
        NdefTemplateMaster master = new NdefTemplateMaster();
        master.usesLRP = isLrpAuthenticationMode;
        master.fileDataLength = 64; // Set to match your encrypted file data length

        String urlTemplate = URL_DOMAIN_TEMPLATE;
        byte[] ndefRecord = master.generateNdefTemplateFromUrlString(urlTemplate, sdmSettings);

        // Write NDEF record to the tag
        try {
            WriteData.run(dnaC, NDEF_FILE_NUMBER, ndefRecord, 0);
            writeToUiAppend(output, "NDEF record with URL template written successfully");
        } catch (IOException e) {
            writeToUiAppend(output, "Failed to write NDEF record: " + e.getMessage());
            throw e;
        }

        // Write file data
        // Generate seed (e.g., 16 bytes)
        byte[] seed = generateSeed(16);
        String seedHex = bytesToHex(seed);

        // Derive the full private key using the seed and APPLICATION_KEY_ETH_DIVERSIFYING
        byte[] derivedPrivateKey = derivePrivateKey(seed, APPLICATION_KEY_ETH_DIVERSIFYING);
        String derivedPrivateKeyHex = bytesToHex(derivedPrivateKey);

        // Generate the corresponding Ethereum address (simplified)
        String ethereumAddress = generateEthereumAddress(derivedPrivateKey);

        // Combine timestamp and seed
        String fileDataString = "#1|" + seedHex;
        byte[] fileData = fileDataString.getBytes(StandardCharsets.UTF_8);

        int fileDataOffset = isLrpAuthenticationMode ? URL_DOMAIN_TEMPLATE_LEN + 16 : URL_DOMAIN_TEMPLATE_LEN;
        try {
            WriteData.run(dnaC, NDEF_FILE_NUMBER, fileData, fileDataOffset);
            writeToUiAppend(output, "File data written successfully");
//            writeToUiAppend(output, "Seed stored: 0x" + seedHex);
            writeToUiAppend(output, "Derived Ethereum private key: 0x" + derivedPrivateKeyHex);
            writeToUiAppend(output, "Corresponding Ethereum address: 0x" + ethereumAddress);
        } catch (IOException e) {
            writeToUiAppend(output, "Failed to write file data: " + e.getMessage());
            throw e;
        }

        writeToUiAppend(output, "URL setup and data writing completed");
    }

    private boolean authenticateWithMasterKey() throws Exception {
        boolean success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, APPLICATION_KEY_DEFAULT);
        if (success) {
            writeToUiAppend(output, "Auth successfully using APPLICATION_KEY_DEFAULT");
            return success;
        }
        else {
            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, MASTER_APPLICATION_KEY);
            if (success) {
                writeToUiAppend(output, "Auth successfully using MASTER_APPLICATION_KEY");
                return success;
            }
        }

        if (!success) {
            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, MASTER_APPLICATION_KEY);
        }
        return success;
    }

    private byte[] generateSeed(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[length];
        secureRandom.nextBytes(seed);
        return seed;
    }

    private byte[] derivePrivateKey(byte[] seed, byte[] applicationKey2) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Combine seed and APPLICATION_KEY_2 to create a unique derivation base
        byte[] combinedInput = new byte[seed.length + applicationKey2.length];
        System.arraycopy(seed, 0, combinedInput, 0, seed.length);
        System.arraycopy(applicationKey2, 0, combinedInput, seed.length, applicationKey2.length);

        String password = bytesToHex(combinedInput); // Use combined input as password
        int iterations = 262144; // Number of iterations (you can adjust this)
        int keyLength = 256; // Desired key length in bits

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT_FOR_DIVERSIFYING, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }


    private String generateEthereumAddress(byte[] privateKey) {
        // This is a simplified version. In a real implementation, you'd use EC multiplication
        byte[] publicKey = getPublicKey(privateKey);

        // Keccak-256 hash of public key
        byte[] hash = keccak256(publicKey);

        // Take last 20 bytes
        byte[] address = new byte[20];
        System.arraycopy(hash, hash.length - 20, address, 0, 20);

        return bytesToHex(address);
    }

    private byte[] getPublicKey(byte[] privateKey) {
        // This is a simplified version. In a real implementation, you'd use EC multiplication
        // For demonstration, we're just using the private key as the public key
        return privateKey;
    }

    private byte[] keccak256(byte[] input) {
        // This is a very basic implementation of Keccak-256
        // In a real-world scenario, you'd use a proper Keccak library
        int[] state = new int[25];
        for (int i = 0; i < input.length; i++) {
            state[i / 4] ^= (input[i] & 0xFF) << (8 * (i % 4));
        }
        for (int round = 0; round < 24; round++) {
            // Simplified Keccak-f[1600] permutation
            // This is not a complete implementation
        }
        byte[] output = new byte[32];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = (byte) (state[i] >>> (8 * j));
            }
        }
        return output;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private void changeKey(int keyNumber, byte[] newKey) throws Exception {
        try {
            if (keyNumber == ACCESS_KEY0) {
                int version = GetKeyVersion.run(dnaC, keyNumber);
                writeToUiAppend(output, "Try change key " + keyNumber + " version " + version);
                ChangeKey.run(dnaC, keyNumber, null, newKey, version);
                writeToUiAppend(output, "Changed key " + keyNumber + " successfully using version " + version);
//                    ChangeKey.run(dnaC, keyNumber, MASTER_APPLICATION_KEY, newKey, Constants.APPLICATION_KEY_VERSION_NEW);
            }
            else {
                // Try to change the key using the default key first
                ChangeKey.run(dnaC, keyNumber, Ntag424.FACTORY_KEY, newKey, Constants.APPLICATION_KEY_VERSION_DEFAULT);
                writeToUiAppend(output, "Changed key " + keyNumber + " successfully using default key");
            }
        } catch (Exception e) {
            // If that fails, try using the custom key
            try {
                if (keyNumber == ACCESS_KEY0) {
                    int version = GetKeyVersion.run(dnaC, keyNumber);
                    writeToUiAppend(output, "Try change key " + keyNumber + " version " + version);
                    ChangeKey.run(dnaC, keyNumber, null, newKey, version);
                    writeToUiAppend(output, "Changed key " + keyNumber + " successfully using version " + version);
//                    ChangeKey.run(dnaC, keyNumber, MASTER_APPLICATION_KEY, newKey, Constants.APPLICATION_KEY_VERSION_NEW);
                } else {
                    byte[] currentKey = getCurrentKey(keyNumber);
                    ChangeKey.run(dnaC, keyNumber, currentKey, newKey, Constants.APPLICATION_KEY_VERSION_NEW);
                }
                writeToUiAppend(output, "Changed key " + keyNumber + " successfully using custom key");
            } catch (Exception e2) {
                writeToUiAppend(output, "Failed to change key " + keyNumber + ": " + e2.getMessage());
//                throw e2;
            }
        }
    }

    private byte[] getCurrentKey(int keyNumber) {
        switch (keyNumber) {
            case ACCESS_KEY1: return APPLICATION_KEY_1;
            case ACCESS_KEY2: return APPLICATION_KEY_2;
            case ACCESS_KEY3: return APPLICATION_KEY_3;
            case ACCESS_KEY4: return APPLICATION_KEY_4;
            default: return APPLICATION_KEY_DEFAULT;
        }
    }

    private void unsetActivty() {
        Log.d(TAG, "UnsetActivity Worker");

        boolean success = false;
        try {
            dnaC = new DnaCommunicator();
            try {
                dnaC.setTransceiver((bytesToSend) -> isoDep.transceive(bytesToSend));
            } catch (NullPointerException npe) {
                writeToUiAppend(output, "Please tap a tag before running any tests, aborted");
                return;
            }
            dnaC.setLogger((info) -> Log.d(TAG, "Communicator: " + info));
            dnaC.beginCommunication();

            /**
             * These steps are running - assuming that all keys are 'default' keys filled with 16 00h values
             * 1) Authenticate with Application Key 00h in AES mode
             * 2) If the authentication in AES mode fails try to authenticate in LRP mode
             * 3) Write the default Capability Container content to file 01
             * 4) Clear the file 02 (fill the 256 bytes with 00h)
             */

            // authentication
            boolean isLrpAuthenticationMode = false;
            byte[] auth_key = Ntag424.FACTORY_KEY;

            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
            if (success) {
                writeToUiAppend(output, "AES Authentication SUCCESS DEFAULT KEY");
            } else {
                auth_key = MASTER_APPLICATION_KEY;
                success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                if (success) {
                    writeToUiAppend(output, "AES Authentication SUCCESS MASTER KEY");
                } else {
                    // if the returnCode is '919d' = permission denied the tag is in LRP mode authentication
                    if (dnaC.getLastCommandResult().status2 == PERMISSION_DENIED) {
                        // try to run the LRP authentication
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "LRP Authentication SUCCESS");
                            isLrpAuthenticationMode = true;
                        } else {
                            writeToUiAppend(output, "LRP Authentication FAILURE");
                            writeToUiAppend(output, "returnCode is " + Utils.byteToHex(dnaC.getLastCommandResult().status2));
                            writeToUiAppend(output, "Authentication not possible, Operation aborted");
                            return;
                        }
                    } else {
                        // any other error, print the error code and return
                        writeToUiAppend(output, "AES Authentication FAILURE");
                        writeToUiAppend(output, "returnCode is " + Utils.byteToHex(dnaC.getLastCommandResult().status2));
                        return;
                    }
                }
            }

            // write CC to file 01
            try {
                WriteData.run(dnaC, CC_FILE_NUMBER, NDEF_FILE_01_CAPABILITY_CONTAINER_DEFAULT, 0);
            } catch (IOException e) {
                Log.e(TAG, "writeData IOException: " + e.getMessage());
                writeToUiAppend(output, "File 01h writeDataIOException: " + e.getMessage());
                writeToUiAppend(output, "Writing the Capability Container FAILURE, Operation aborted");
                return;
            }
            writeToUiAppend(output, "File 01h Writing the Capability Container SUCCESS");

            // Clear the file 02 (fill the 256 bytes with 00h)
            FileSettings fileSettings02 = null;
            try {
                fileSettings02 = GetFileSettings.run(dnaC, NDEF_FILE_NUMBER);
            } catch (Exception e) {
                Log.e(TAG, "getFileSettings File 02 Exception: " + e.getMessage());
                writeToUiAppend(output, "getFileSettings File 02 Exception: " + e.getMessage());
            }
            if (fileSettings02 == null) {
                Log.e(TAG, "getFileSettings File 02 Error, Operation aborted");
                writeToUiAppend(output, "getFileSettings File 02 Error, Operation aborted");
                return;
            }
            // new settings
            SDMSettings sdmSettings = new SDMSettings();
            sdmSettings.sdmEnabled = false; // at this point we are just preparing the templated but do not enable the SUN/SDM feature
            sdmSettings.sdmMetaReadPerm = ACCESS_NONE; // Set to a key to get encrypted PICC data
            sdmSettings.sdmFileReadPerm = ACCESS_NONE;  // Used to create the MAC and Encrypt FileData
            sdmSettings.sdmReadCounterRetrievalPerm = ACCESS_NONE; // Not sure what this is for
            sdmSettings.sdmOptionEncryptFileData = false;
            fileSettings02.sdmSettings = sdmSettings;
            fileSettings02.readWritePerm = ACCESS_EVERYONE;
            fileSettings02.changePerm = ACCESS_KEY0;
            fileSettings02.readPerm = ACCESS_EVERYONE;
            fileSettings02.writePerm = ACCESS_EVERYONE;

            try {
                ChangeFileSettings.run(dnaC, NDEF_FILE_NUMBER, fileSettings02);
            } catch (IOException e) {
                Log.e(TAG, "ChangeFileSettings IOException: " + e.getMessage());
                writeToUiAppend(output, "ChangeFileSettings File 02 Error, Operation aborted");
                return;
            }

            // writing blanks to the file to clear, running in 6 writing sequences
            byte[] bytes51Blank = new byte[51];
            byte[] bytes01Blank = new byte[1];
            try {
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes51Blank.clone(), 51 * 0);
                Log.d(TAG, "Clearing File 02 done part 1");
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes51Blank.clone(), 51 * 1);
                Log.d(TAG, "Clearing File 02 done part 2");
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes51Blank.clone(), 51 * 2);
                Log.d(TAG, "Clearing File 02 done part 3");
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes51Blank.clone(), 51 * 3);
                Log.d(TAG, "Clearing File 02 done part 4");
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes51Blank.clone(), 51 * 4);
                Log.d(TAG, "Clearing File 02 done part 5");
                WriteData.run(dnaC, NDEF_FILE_NUMBER, bytes01Blank.clone(), 51 * 5);
                Log.d(TAG, "Clearing File 02 done part 6");
            } catch (IOException e) {
                Log.e(TAG, "writeData IOException: " + e.getMessage());
                writeToUiAppend(output, "File 02h Clearing writeDataIOException: " + e.getMessage());
                writeToUiAppend(output, "Clearing the File 02 FAILURE, Operation aborted");
                return;
            }
            writeToUiAppend(output, "File 02h Clearing SUCCESS");

            // change the application keys 3 + 4 from custom back to default keys
            // to change the keys we need an authentication with application key 0 = master application key
            // authentication
            if (!isLrpAuthenticationMode) {
                success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
            } else {
                success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
            }
            if (success) {
                writeToUiAppend(output, "Authentication SUCCESS");
            } else {
                writeToUiAppend(output, "Authentication FAILURE");
                writeToUiAppend(output, "Authentication not possible, Operation aborted");
                return;
            }

            // change application key 1
            success = false;
            try {
                ChangeKey.run(dnaC, ACCESS_KEY1, APPLICATION_KEY_1, APPLICATION_KEY_DEFAULT, APPLICATION_KEY_VERSION_DEFAULT);
                success = true;
            } catch (IOException e) {
                Log.e(TAG, "ChangeKey 1 IOException: " + e.getMessage());
            }
            if (success) {
                writeToUiAppend(output, "Change Application Key 1 SUCCESS");
            } else {
                writeToUiAppend(output, "Change Application Key 1 FAILURE (maybe the key is already the FACTORY key ?)");
                // silent authenticate with Access Key 0 as we had a failure
                if (!isLrpAuthenticationMode) {
                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                } else {
                    success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                }
                if (!success) {
                    writeToUiAppend(output, "Error on Authentication with ACCESS KEY 0, aborted");
                    return;
                }
            }

            // change application key 2
            success = false;
            try {
                ChangeKey.run(dnaC, ACCESS_KEY2, APPLICATION_KEY_2, APPLICATION_KEY_DEFAULT, APPLICATION_KEY_VERSION_DEFAULT);
                success = true;
            } catch (IOException e) {
                Log.e(TAG, "ChangeKey 2 IOException: " + e.getMessage());
            }
            if (success) {
                writeToUiAppend(output, "Change Application Key 2 SUCCESS");
            } else {
                writeToUiAppend(output, "Change Application Key 2 FAILURE (maybe the key is already the FACTORY key ?)");
                // silent authenticate with Access Key 0 as we had a failure
                if (!isLrpAuthenticationMode) {
                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                } else {
                    success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                }
                if (!success) {
                    writeToUiAppend(output, "Error on Authentication with ACCESS KEY 0, aborted");
                    return;
                }
            }

            // change application key 3
            success = false;
            try {
                ChangeKey.run(dnaC, ACCESS_KEY3, APPLICATION_KEY_3, APPLICATION_KEY_DEFAULT, APPLICATION_KEY_VERSION_DEFAULT);
                success = true;
            } catch (IOException e) {
                Log.e(TAG, "ChangeKey 3 IOException: " + e.getMessage());
            }
            if (success) {
                writeToUiAppend(output, "Change Application Key 3 SUCCESS");
            } else {
                writeToUiAppend(output, "Change Application Key 3 FAILURE (maybe the key is already the FACTORY key ?)");
                // silent authenticate with Access Key 0 as we had a failure
                if (!isLrpAuthenticationMode) {
                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                } else {
                    success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                }
                if (!success) {
                    writeToUiAppend(output, "Error on Authentication with ACCESS KEY 0, aborted");
                    return;
                }
            }


            // change application key 4
            // this key can be static or diversified
            success = false;
            try {
                ChangeKey.run(dnaC, ACCESS_KEY4, APPLICATION_KEY_4, APPLICATION_KEY_DEFAULT, APPLICATION_KEY_VERSION_DEFAULT);
                success = true;
            } catch (IOException e) {
                Log.e(TAG, "ChangeKey 4 IOException: " + e.getMessage());
            }
            if (success) {
                writeToUiAppend(output, "Change Application Key 4 SUCCESS");
            } else {
                writeToUiAppend(output, "Change Application Key 4 FAILURE (maybe the key is already the FACTORY or DIVERSED key ?)");
            }

            // if no success try with the diversified key, but first authenticate again
            if (!success) {
                // silent authenticate with Access Key 0 as we had a failure
                if (!isLrpAuthenticationMode) {
                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                } else {
                    success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                }
                if (!success) {
                    writeToUiAppend(output, "Error on Authentication with ACCESS KEY 0, aborted");
                    return;
                }
                // now get the real tag UID
                // get the real card UID
                byte[] realTagUid = null;
                try {
                    realTagUid = GetCardUid.run(dnaC);
                    Log.d(TAG, Utils.printData("real Tag UID", realTagUid));
                } catch (ProtocolException e) {
                    writeToUiAppend(output, "Could not read the real Tag UID, aborted");
                    writeToUiAppend(output, "returnCode is " + Utils.byteToHex(dnaC.getLastCommandResult().status2));
                    return;
                }
                // derive the Master Application key with real Tag UID
                KeyInfo keyInfo = new KeyInfo();
                keyInfo.diversifyKeys = true;
                keyInfo.key = MASTER_APPLICATION_KEY_FOR_DIVERSIFYING.clone();
                keyInfo.systemIdentifier = SYSTEM_IDENTIFIER_FOR_DIVERSIFYING; // static value for this application
                byte[] diversifiedKey = keyInfo.generateKeyForCardUid(realTagUid);
                Log.d(TAG, Utils.printData("diversifiedKey", diversifiedKey));
                success = false;
                try {
                    ChangeKey.run(dnaC, ACCESS_KEY4, diversifiedKey, APPLICATION_KEY_DEFAULT, APPLICATION_KEY_VERSION_DEFAULT);
                    success = true;
                } catch (IOException e) {
                    Log.e(TAG, "ChangeKey 4 IOException: " + e.getMessage());
                }
                if (success) {
                    writeToUiAppend(output, "Change Application Key 4 SUCCESS");
                } else {
                    writeToUiAppend(output, "Change Application Key 4 FAILURE (UNKNOWN key)");
                }


            }

            //Change to factory MASTER KEY

            success = false;
            try {
                AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                int version = GetKeyVersion.run(dnaC, ACCESS_KEY0);
                writeToUiAppend(output, "Try change key " + ACCESS_KEY0 + " version " + version);
                ChangeKey.run(dnaC, ACCESS_KEY0, null, Ntag424.FACTORY_KEY, version);
                success = true;
            } catch (IOException e) {
                Log.e(TAG, "ChangeKey 0 IOException: " + e.getMessage());
            }
            if (success) {
                writeToUiAppend(output, "Change Application Key 0 SUCCESS");
            } else {
                writeToUiAppend(output, "Change Application Key 0 FAILURE");
            }
            writeToUiAppend(output, "== UNSET DONE ==");
            vibrateShort();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

        /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mReturnHome = menu.findItem(R.id.action_return_home);
        mReturnHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(EncryptedFileSunCustomKeysActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}