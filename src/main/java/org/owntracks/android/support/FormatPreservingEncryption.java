package org.owntracks.android.support;

import android.util.Base64;

import ch.bfh.fpelib.Key;
import ch.bfh.fpelib.RankThenEncipher;
import ch.bfh.fpelib.intEnc.FFXIntegerCipher;
import ch.bfh.fpelib.intEnc.KnuthShuffleCipher;
import ch.bfh.fpelib.messageSpace.StringMessageSpace;
import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FormatPreservingEncryption {

    //Format (regex or max value) definitions for JSON elements to be encrypted
    private static final String TYPES_IMPLEMENTED = "(location|waypoint|transition)";
    private static final BigInteger ALT_MAX = BigInteger.valueOf(10000);
    private static final BigInteger BATT_MAX = BigInteger.valueOf(100);
    private static final BigInteger COG_MAX = BigInteger.valueOf(359);
    private static final String LAT_REGEXP = "-?(90|([0-9]|[1-8][0-9])(\\.[0-9]{1,8})?)";
    private static final String LON_REGEXP = "-?(180|([0-9]|[0-9][0-9]|1[0-7][0-9])(\\.[0-9]{1,8})?)";
    private static final BigInteger TST_MAX = BigInteger.valueOf(4131648000L);

    //Initialization of various FPE-ciphers for each JSON element depending on the format
    private static final FFXIntegerCipher ALT = new FFXIntegerCipher(ALT_MAX);
    private static final KnuthShuffleCipher BATT = new KnuthShuffleCipher(BATT_MAX);
    private static final KnuthShuffleCipher COG = new KnuthShuffleCipher(COG_MAX);
    private static final StringMessageSpace LAT_MS = new StringMessageSpace(LAT_REGEXP);
    private static final RankThenEncipher<String> LAT = new RankThenEncipher<>(LAT_MS);
    private static final StringMessageSpace LON_MS = new StringMessageSpace(LON_REGEXP);
    private static final RankThenEncipher<String> LON = new RankThenEncipher<>(LON_MS);
    private static final FFXIntegerCipher TST = new FFXIntegerCipher(TST_MAX);


    /**
     * Empty private constructor to avoid instantiation of this helper class
     */
    private FormatPreservingEncryption(){}


    /**
     * Creates a new JSONObject from a JSON string
     * @param jsonMessage JSON message as string
     * @return JSON object
     */
    public static JSONObject getJsonMessage(String jsonMessage) {
        try {
            return new JSONObject(jsonMessage);
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }


    /**
     * Encrypt predefined elements in the JSON object with FPE techniques
     * @param json  JSON Plaintext
     * @param key   Randomly computed key
     * @param tweak Arbitrary bytes to prevent deterministic encryption
     * @return JSON object with encrypted elements
     */
    public static JSONObject encrypt(JSONObject json, Key key, byte[] tweak) {
        if (!json.optString("_type").matches(TYPES_IMPLEMENTED)) {
            //if message type not supported return original
            return json;
        }
        JSONObject encryptedJson = new JSONObject();
        Iterator<String> entries = json.keys();
        while (entries.hasNext()) {
            String entry = entries.next();
            Object value;
            try {
                switch (entry) {
                    case "alt":
                        value = ALT.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "batt":
                        value = BATT.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "cog":
                        value = COG.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "desc":
                        try {
                            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            Key aesTweak = new Key(tweak);
                            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getKey(16), "AES"), new IvParameterSpec(aesTweak.getKey(16)));
                            byte[] encrypted = aes.doFinal(json.getString(entry).getBytes(Charset.forName("UTF-8")));
                            value = Base64.encode(encrypted, Base64.DEFAULT);
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unexpected exception. " + e.getMessage());
                        }
                        break;
                    case "lat":
                        value = LAT.encrypt(json.getString(entry), key, tweak);
                        break;
                    case "lon":
                        value = LON.encrypt(json.getString(entry), key, tweak);
                        break;
                    case "wtst":
                        value = TST.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).longValue();
                        break;
                    default: //all other entries are not encrypted
                        value = json.get(entry);
                        break;
                }
                encryptedJson.put(entry, value);
            } catch (JSONException e) {
                throw new RuntimeException("Unexpected exception. " + e.getMessage());
            }
        }
        return encryptedJson;
    }


    /**
     * Decrypt predefined elements in the JSON object with FPE techniques
     * @param json  JSON Ciphertext
     * @param key   Randomly computed key
     * @param tweak Arbitrary bytes to prevent deterministic encryption
     * @return Decrypted JSON object
     */
    public static JSONObject decrypt(JSONObject json, Key key, byte[] tweak) {
        if (!json.optString("_type").matches(TYPES_IMPLEMENTED)) {
            //if message type not supported return original
            return json;
        }
        JSONObject decryptedJson = new JSONObject();
        Iterator<String> entries = json.keys();
        while (entries.hasNext()) {
            String entry = entries.next();
            Object value;
            try {
                switch (entry) {
                    case "alt":
                        value = ALT.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "batt":
                        value = BATT.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "cog":
                        value = COG.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue();
                        break;
                    case "desc":
                        try {
                            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            Key aesTweak = new Key(tweak);
                            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getKey(16), "AES"), new IvParameterSpec(aesTweak.getKey(16)));
                            byte[] decoded = Base64.decode(json.getString(entry).getBytes(Charset.forName("UTF-8")), Base64.DEFAULT);
                            value = new String(aes.doFinal(decoded), Charset.forName("UTF-8"));
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unexpected exception. " + e.getMessage());
                        }
                        break;
                    case "lat":
                        value = LAT.decrypt(json.getString(entry), key, tweak);
                        break;
                    case "lon":
                        value = LON.decrypt(json.getString(entry), key, tweak);
                        break;
                    case "wtst":
                        value = TST.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).longValue();
                        break;
                    default: //all other entries are not decrypted
                        value = json.get(entry);
                        break;
                }
                decryptedJson.put(entry, value);
            } catch (JSONException e) {
                throw new RuntimeException("Unexpected exception. " + e.getMessage());
            }
        }
        return decryptedJson;
    }


    /**
     * Stores username and password in the SharedPreferences
     * @param username Username to store
     * @param password Password according to username
     */
    public static void setPassword(String username, String password) {
        deletePassword(username); //First remove old password of user if exists, before storing the new one
        HashSet<String> userPWs = new HashSet<String>(Preferences.getSharedPreferences().getStringSet("userPasswords", new HashSet<String>()));
        userPWs.add(username + "$" + password);
        Preferences.getSharedPreferences().edit().putStringSet("userPasswords", userPWs).commit();
    }


    /**
     * Deletes username and password of a given user from the SharedPreferences
     * @param username User to delete
     */
    public static void deletePassword(String username) {
        HashSet<String> userPWs = new HashSet<String>(Preferences.getSharedPreferences().getStringSet("userPasswords", new HashSet<String>()));
        for (String userPW : userPWs) {
            if (userPW.contains(username)) {
                userPWs.remove(userPW);
                break;
            }
        }
        Preferences.getSharedPreferences().edit().putStringSet("userPasswords", userPWs).commit();
    }


    /**
     * Returns the password of a given user
     * @param username User of the password
     * @return Password of the user
     */
    public static String getPassword(String username) {
        HashSet<String> userPWs = new HashSet<String>(Preferences.getSharedPreferences().getStringSet("userPasswords", new HashSet<String>()));
        String password = "";

        for (String userPW : userPWs) {
            String userPWLowerCase = userPW.toLowerCase();
            if (userPWLowerCase.contains(username.toLowerCase())) {
                password = userPW.substring(userPW.indexOf("$") + 1);
                return password;
            }
        }
        return null;
    }


    /**
     * Returns all users as string array
     * @return String array with all usernames
     */
    public static String[] loadUsers() {
        HashSet<String> userSet = new HashSet<String>(Preferences.getSharedPreferences().getStringSet("userPasswords", new HashSet<String>()));
        String[] users = userSet.toArray(new String[userSet.size()]);

        for (int i = 0; i < users.length; i++) {
            users[i] = users[i].substring(0, users[i].indexOf("$"));
        }
        return users;
    }
}