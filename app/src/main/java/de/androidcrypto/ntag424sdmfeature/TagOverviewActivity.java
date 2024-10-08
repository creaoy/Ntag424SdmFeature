package de.androidcrypto.ntag424sdmfeature;

import static net.bplearning.ntag424.CommandResult.PERMISSION_DENIED;
import static net.bplearning.ntag424.constants.Ntag424.CC_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Ntag424.DATA_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Ntag424.NDEF_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_EVERYONE;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY0;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY1;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY2;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY3;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY4;
import static de.androidcrypto.ntag424sdmfeature.Constants.MASTER_APPLICATION_KEY;
import static de.androidcrypto.ntag424sdmfeature.Constants.MASTER_APPLICATION_KEY_FOR_DIVERSIFYING;
import static de.androidcrypto.ntag424sdmfeature.Constants.SYSTEM_IDENTIFIER_FOR_DIVERSIFYING;

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
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.card.KeyInfo;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.ReadData;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.exception.ProtocolException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TagOverviewActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = TagOverviewActivity.class.getSimpleName();
    private com.google.android.material.textfield.TextInputEditText output;
    private DnaCommunicator dnaC = new DnaCommunicator();
    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_tag_overview);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
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
        Log.d(TAG, "Tag Overview Activity Worker");
        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
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
                     * These steps are running - this activity tries to get an overview about the tag
                     *
                     * assuming that all keys are 'default' keys filled with 16 00h values
                     * 1) Authenticate with Application Key 00h in AES mode
                     * 2) If the authentication in AES mode fails try to authenticate in LRP mode
                     * 3) Write an URL template to file 02 with Uid and/or Counter plus CMAC
                     * 4) Get existing file settings for file 02
                     * 5) Save the modified file settings back to the tag
                     */

                    writeToUiAppend(output, Constants.DOUBLE_DIVIDER);
                    // authentication
                    boolean isLrpAuthenticationMode = false;

                    writeToUiAppend(output, "Authentication with FACTORY ACCESS_KEY 0");
                    // what happens when we choose the wrong authentication scheme ?
                    byte [] auth_key = Ntag424.FACTORY_KEY;

                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                    if (success) {
                        writeToUiAppend(output, "AES Authentication SUCCESS DEFAULT KEY");
                    } else {
                        auth_key = MASTER_APPLICATION_KEY;
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                        if (success) {
                            writeToUiAppend(output, "AES Authentication SUCCESS MASTER KEY");
                        }
                        else {
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

                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);
                    // check all other application keys (1..4) if they are FACTORY or CUSTOM
                    int key1State = 0; // 0 = no auth, 1 = FACTORY key SUCCESS, 2 = CUSTOM key SUCCESS, 3 = diversified key SUCCESS, 4 = UNKNOWN key, failure
                    int key2State = 0;
                    int key3State = 0;
                    int key4State = 0;
                    if (!isLrpAuthenticationMode) {
                        // app key 1
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY1, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 1 is FACTORY key");
                            key1State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY1, Constants.APPLICATION_KEY_1);
                            if (success) {
                                writeToUiAppend(output, "App Key 1 is CUSTOM key");
                                key1State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 1 has UNKNOWN key");
                                key1State = 4;
                            }
                        }
                        // app key 2
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY2, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 2 is FACTORY key");
                            key2State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY2, Constants.APPLICATION_KEY_2);
                            if (success) {
                                writeToUiAppend(output, "App Key 2 is CUSTOM key");
                                key2State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 2 has UNKNOWN key");
                                key2State = 4;
                            }
                        }
                        // app key 3
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY3, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 3 is FACTORY key");
                            key3State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY3, Constants.APPLICATION_KEY_3);
                            if (success) {
                                writeToUiAppend(output, "App Key 3 is CUSTOM key");
                                key3State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 3 has UNKNOWN key");
                                key3State = 4;
                            }
                        }
                        // app key 4
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY4, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 4 is FACTORY key");
                            key4State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY4, Constants.APPLICATION_KEY_4);
                            if (success) {
                                writeToUiAppend(output, "App Key 4 is CUSTOM key");
                                key4State = 2;
                            } else {
                                // the key could be diversified
                                // silent authenticate with Access Key 0 as we had a failure
                                success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
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
                                // diversify the Master Application key with real Tag UID
                                KeyInfo keyInfo = new KeyInfo();
                                keyInfo.diversifyKeys = true;
                                keyInfo.key = MASTER_APPLICATION_KEY_FOR_DIVERSIFYING.clone();
                                keyInfo.systemIdentifier = SYSTEM_IDENTIFIER_FOR_DIVERSIFYING; // static value for this application
                                byte[] diversifiedKey = keyInfo.generateKeyForCardUid(realTagUid);
                                Log.d(TAG, Utils.printData("diversifiedKey", diversifiedKey));
                                // authenticate with diversified key
                                success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY4, diversifiedKey);
                                if (success) {
                                    writeToUiAppend(output, "App Key 4 is DIVERSIFIED key");
                                    key4State = 3;
                                } else {
                                    writeToUiAppend(output, "App Key 4 has UNKNOWN key");
                                    key4State = 4;
                                }
                            }
                        }
                    } else {
                        // app key 1
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY1, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 1 is FACTORY key");
                            key1State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY1, Constants.APPLICATION_KEY_1);
                            if (success) {
                                writeToUiAppend(output, "App Key 1 is CUSTOM key");
                                key1State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 1 has UNKNOWN key");
                                key1State = 3;
                            }
                        }
                        // app key 2
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY2, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 2 is FACTORY key");
                            key2State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY2, Constants.APPLICATION_KEY_2);
                            if (success) {
                                writeToUiAppend(output, "App Key 2 is CUSTOM key");
                                key2State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 2 has UNKNOWN key");
                                key2State = 3;
                            }
                        }
                        // app key 3
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY3, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 3 is FACTORY key");
                            key3State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY3, Constants.APPLICATION_KEY_3);
                            if (success) {
                                writeToUiAppend(output, "App Key 3 is CUSTOM key");
                                key3State = 2;
                            } else {
                                writeToUiAppend(output, "App Key 3 has UNKNOWN key");
                                key3State = 3;
                            }
                        }
                        // app key 4
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY4, Ntag424.FACTORY_KEY);
                        if (success) {
                            writeToUiAppend(output, "App Key 4 is FACTORY key");
                            key4State = 1;
                        } else {
                            // try to authenticate with custom key
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY4, Constants.APPLICATION_KEY_4);
                            if (success) {
                                writeToUiAppend(output, "App Key 4 is CUSTOM key");
                                key4State = 2;
                            } else {
                                // the key could be diversified
                                // silent authenticate with Access Key 0 as we had a failure
                                success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
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
                                // diversify the Master Application key with real Tag UID
                                KeyInfo keyInfo = new KeyInfo();
                                keyInfo.diversifyKeys = true;
                                keyInfo.key = MASTER_APPLICATION_KEY_FOR_DIVERSIFYING.clone();
                                keyInfo.systemIdentifier = SYSTEM_IDENTIFIER_FOR_DIVERSIFYING; // static value for this application
                                byte[] diversifiedKey = keyInfo.generateKeyForCardUid(realTagUid);
                                Log.d(TAG, Utils.printData("diversifiedKey", diversifiedKey));
                                // authenticate with diversified key
                                success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY4, diversifiedKey);
                                if (success) {
                                    writeToUiAppend(output, "App Key 4 is DIVERSIFIED key");
                                    key4State = 3;
                                } else {
                                    writeToUiAppend(output, "App Key 4 has UNKNOWN key");
                                    key4State = 4;
                                }
                            }
                        }
                    }
                    writeToUiAppend(output, Constants.DOUBLE_DIVIDER);

                    // silent authenticate with Access Key 0, should work
                    if (!isLrpAuthenticationMode) {
                        success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, auth_key);
                    } else {
                        success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                    }
                    if (!success) {
                        writeToUiAppend(output, "Error on Authentication with ACCESS KEY 0, aborted");
                        return;
                    }
                    int lastAuthKeyNumber = 0;

                    // get the file settings
                    writeToUiAppend(output, "Get the File Settings");
                    FileSettings fileSettings01;
                    try {
                        fileSettings01 = GetFileSettings.run(dnaC, CC_FILE_NUMBER);
                    } catch (Exception e) {
                        Log.e(TAG, "getFileSettings File 01 Exception: " + e.getMessage());
                        writeToUiAppend(output, "getFileSettings File 01 Exception: " + e.getMessage());
                        return;
                    }
                    writeToUiAppend(output, DnacFileSettingsDumper.run(CC_FILE_NUMBER, fileSettings01));
                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);

                    FileSettings fileSettings02;
                    try {
                        fileSettings02 = GetFileSettings.run(dnaC, NDEF_FILE_NUMBER);
                    } catch (Exception e) {
                        Log.e(TAG, "getFileSettings File 02 Exception: " + e.getMessage());
                        writeToUiAppend(output, "getFileSettings File 02 Exception: " + e.getMessage());
                        return;
                    }
                    writeToUiAppend(output, DnacFileSettingsDumper.run(NDEF_FILE_NUMBER, fileSettings02));
                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);

                    FileSettings fileSettings03;
                    try {
                        fileSettings03 = GetFileSettings.run(dnaC, DATA_FILE_NUMBER);
                    } catch (Exception e) {
                        Log.e(TAG, "getFileSettings File 03 Exception: " + e.getMessage());
                        writeToUiAppend(output, "getFileSettings File 03 Exception: " + e.getMessage());
                        return;
                    }
                    writeToUiAppend(output, DnacFileSettingsDumper.run(DATA_FILE_NUMBER, fileSettings03));
                    writeToUiAppend(output, Constants.DOUBLE_DIVIDER);

                    // read the content of each file
                    // check which key in required to read the file
                    int file01RAccess = fileSettings01.readPerm;
                    if (file01RAccess == ACCESS_EVERYONE) {
                        // do not need to run any authentication
                    } else {
                        // authenticate with file01RAccess key
                        if (file01RAccess != lastAuthKeyNumber) {
                            // the requested key is different from the last auth key
                            // did we had a successful authentication with this key ? with FACTORY or CUSTOM key ?

                            if (!isLrpAuthenticationMode) {
                                success = AESEncryptionMode.authenticateEV2(dnaC, file01RAccess, Ntag424.FACTORY_KEY);
                            } else {
                                success = LRPEncryptionMode.authenticateLRP(dnaC, file01RAccess, Ntag424.FACTORY_KEY);
                            }
                            if (!success) {
                                writeToUiAppend(output, "Error on Authentication with key " + file01RAccess  + ", aborted");
                                return;
                            }
                            lastAuthKeyNumber = file01RAccess;
                        }
                    }
                    byte[] fileContent01 = runReadData(CC_FILE_NUMBER, 0, 32);
                    writeToUiAppend(output, Utils.printData("content of file 01", fileContent01));
                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);

                    // check which key in required to read the file
                    int file02RAccess = fileSettings02.readPerm;
                    if (file02RAccess == ACCESS_EVERYONE) {
                        // do not need to run any authentication
                    } else {
                        // authenticate with file02RAccess key
                        if (file02RAccess != lastAuthKeyNumber) {
                            // the requested key is different from the last auth key
                            // did we had a successful authentication with this key ? with FACTORY or CUSTOM key ?

                            if (!isLrpAuthenticationMode) {
                                success = AESEncryptionMode.authenticateEV2(dnaC, file02RAccess, auth_key);
                            } else {
                                success = LRPEncryptionMode.authenticateLRP(dnaC, file02RAccess, Ntag424.FACTORY_KEY);
                            }
                            if (!success) {
                                writeToUiAppend(output, "Error on Authentication with key " + file02RAccess  + ", aborted");
                                return;
                            }
                            lastAuthKeyNumber = file02RAccess;
                        }
                    }
                    byte[] fileContent02 = runReadData(NDEF_FILE_NUMBER, 0, 256);
                    writeToUiAppend(output, Utils.printData("content of file 02", fileContent02));
                    writeToUiAppend(output,"");
                    writeToUiAppend(output, "ASCII Data: " + new String(fileContent02, StandardCharsets.UTF_8));
                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);

                    // check which key in required to read the file
                    int file03RAccess = fileSettings03.readPerm;
                    if (file03RAccess == ACCESS_EVERYONE) {
                        // do not need to run any authentication
                    } else {
                        // authenticate with file03RAccess key
                        if (file03RAccess != lastAuthKeyNumber) {
                            // the requested key is different from the last auth key
                            // did we had a successful authentication with this key ? with FACTORY or CUSTOM key ?

                            if (!isLrpAuthenticationMode) {
                                success = AESEncryptionMode.authenticateEV2(dnaC, file03RAccess, Ntag424.FACTORY_KEY);
                            } else {
                                success = LRPEncryptionMode.authenticateLRP(dnaC, file03RAccess, Ntag424.FACTORY_KEY);
                            }
                            if (!success) {
                                writeToUiAppend(output, "Error on Authentication with key " + file03RAccess  + ", aborted");
                                return;
                            }
                            lastAuthKeyNumber = file03RAccess;
                        }
                    }
                    byte[] fileContent03 = runReadData( DATA_FILE_NUMBER, 0, 128);
                    writeToUiAppend(output, Utils.printData("content of file 03", fileContent03));
                    writeToUiAppend(output, Constants.SINGLE_DIVIDER);

                } catch (IOException e) {
                    Log.e(TAG, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                }
                writeToUiAppend(output, "== FINISHED ==");
                vibrateShort();
            }
        });
        worker.start();
    }

    private byte[] runReadData(int fileNum, int offset, int length) {
        byte[] data = null;
        try {
            data = ReadData.run(dnaC, fileNum, offset, length);
        } catch (IOException e) {
            Log.e(TAG, "readData IOException: " + e.getMessage());
            writeToUiAppend(output, "readData IOException: " + e.getMessage());
        }
        return data;
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
                Intent intent = new Intent(TagOverviewActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}