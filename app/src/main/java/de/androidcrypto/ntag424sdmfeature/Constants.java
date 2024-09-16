package de.androidcrypto.ntag424sdmfeature;

public class Constants {
    public static final String SINGLE_DIVIDER = "----------------------------";
    public static final String DOUBLE_DIVIDER = "============================";
    public static final String URL_DOMAIN = "http://sdm.phygitalmining.com/";
    public static final String URL_DOMAIN_TEMPLATE = "http://sdm.phygitalmining.com/tag?picc_data={PICC}&enc={FILE}&cmac={MAC}";
    public static final int URL_DOMAIN_TEMPLATE_LEN = 88;


    // application keys are AES-128 = 16 bytes long values
    public static final byte[] APPLICATION_KEY_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    public static final byte[] APPLICATION_KEY_1 = Utils.hexStringToByteArray("3E21DEFFEFAEBB9356F3D5DD65B6AFB7");
    public static final byte[] APPLICATION_KEY_2 = Utils.hexStringToByteArray("418BCEF72CC0EABA447934B03AE61B18");
    public static final byte[] APPLICATION_KEY_3 = Utils.hexStringToByteArray("E43334222ECB4F0D425CFFF0E1D5898B");
    public static final byte[] APPLICATION_KEY_4 = Utils.hexStringToByteArray("3FCB0C6B7B7FA60D6F192A814DF2D8F4");
    public static final byte[] MASTER_APPLICATION_KEY = Utils.hexStringToByteArray("A4F01C717BCB3E67D9462B4FA8CBAF1F");
    public static final byte[] MASTER_APPLICATION_KEY_FOR_DIVERSIFYING = Utils.hexStringToByteArray("96D4F68C514DE8BF510CB347BB7B3CDC");
    public static final byte[] SYSTEM_IDENTIFIER_FOR_DIVERSIFYING = Utils.hexStringToByteArray("666F6F");
    public static final int APPLICATION_KEY_VERSION_DEFAULT = 0;
    public static final int APPLICATION_KEY_VERSION_NEW = 1;
    public static final byte[] SALT_FOR_DIVERSIFYING = Utils.hexStringToByteArray("A1C4AEC48E57A6322B8BBE840127134B");
    public static final byte[] APPLICATION_KEY_ETH_DIVERSIFYING = Utils.hexStringToByteArray("4A4515FFA24E74C6454453A2ABABF2A8");

    // capability container in file 01
    public static final byte[] NDEF_FILE_01_CAPABILITY_CONTAINER_DEFAULT = Utils.hexStringToByteArray("001720010000FF0406E104010000000506E10500808283000000000000000000"); // Free Read & Write Access
    public static final byte[] NDEF_FILE_01_CAPABILITY_CONTAINER_R = Utils.hexStringToByteArray("000F20003A00340406E104010000FF"); // Free Read Access only, no Write Access

    // returnCode from DnaCommunicator
    // byte[] retCode = dnaC.returnCode.clone();
    public static final byte[] PERMISSION_DENIED_ERROR = Utils.hexStringToByteArray("919d");
}