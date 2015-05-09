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
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FormatPreservingEncryption {

    public static final String TYPES_IMPLEMENTED = "(location|waypoint|transition)";
    public static final BigInteger ALT_MAX = BigInteger.valueOf(10000);
    public static final BigInteger BATT_MAX = BigInteger.valueOf(100);
    public static final BigInteger COG_MAX = BigInteger.valueOf(359);
    public static final String LAT_REGEXP = "-?(90|([0-9]|[1-8][0-9])(\\.[0-9]{1,8})?)";
    public static final String LON_REGEXP = "-?(180|([0-9]|[0-9][0-9]|1[0-7][0-9])(\\.[0-9]{1,8})?)";
    public static final BigInteger TST_MAX = BigInteger.valueOf(4131648000L);

    public static final FFXIntegerCipher ALT = new FFXIntegerCipher(ALT_MAX);
    public static final KnuthShuffleCipher BATT = new KnuthShuffleCipher(BATT_MAX);
    public static final KnuthShuffleCipher COG = new KnuthShuffleCipher(COG_MAX);
    public static final StringMessageSpace LAT_MS = new StringMessageSpace(LAT_REGEXP);
    public static final RankThenEncipher<String> LAT = new RankThenEncipher<>(LAT_MS);
    public static final StringMessageSpace LON_MS = new StringMessageSpace(LON_REGEXP);
    public static final RankThenEncipher<String> LON = new RankThenEncipher<>(LON_MS);
    public static final FFXIntegerCipher TST = new FFXIntegerCipher(TST_MAX);

    public static JSONObject encrypt(JSONObject json, Key key, byte[] tweak) {
        if (!json.optString("_type").matches(TYPES_IMPLEMENTED)) {
            throw new RuntimeException("Encryption of message type '" + json.optString("_type") + "' is not implemented.");
        }
        JSONObject encryptedJson = new JSONObject();
        Iterator<String> entries = json.keys();
        while (entries.hasNext()) {
            String entry = entries.next();
            Object value;
            try {
                switch (entry) {
                    case "alt":
                        value = ALT.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "batt":
                        value = BATT.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "cog":
                        value = COG.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "desc":
                        try {
                            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            Key aesTweak = new Key(tweak);
                            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getKey(16), "AES"),new IvParameterSpec(aesTweak.getKey(16)));
                            byte[] encrypted = aes.doFinal(json.getString(entry).getBytes(Charset.forName("UTF-8")));
                            value = Base64.encode(encrypted, Base64.DEFAULT);
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unexpected exception. " + e.getMessage());
                        }
                    case "lat":
                        value = LAT.encrypt(json.getString(entry), key, tweak); break;
                    case "lon":
                        value = LON.encrypt(json.getString(entry), key, tweak); break;
                    case "tst":
                    case "wtst":
                        value = TST.encrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).longValue(); break;
                    default: //all other entries are not encrypted
                        value = json.get(entry); break;
                }
                encryptedJson.put(entry, value);
            }
            catch (JSONException e) {
                throw new RuntimeException("Unexpected exception. " + e.getMessage());
            }
        }
        return encryptedJson;
    }

    public static JSONObject decrypt(JSONObject json, Key key, byte[] tweak) {
        if (!json.optString("_type").matches(TYPES_IMPLEMENTED)) {
            throw new RuntimeException("Decryption of message type '" + json.optString("_type") + "' is not implemented.");
        }
        JSONObject decryptedJson = new JSONObject();
        Iterator<String> entries = json.keys();
        while (entries.hasNext()) {
            String entry = entries.next();
            Object value;
            try {
                switch (entry) {
                    case "alt":
                        value = ALT.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "batt":
                        value = BATT.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "cog":
                        value = COG.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).intValue(); break;
                    case "desc":
                        try {
                            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            Key aesTweak = new Key(tweak);
                            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getKey(16), "AES"),new IvParameterSpec(aesTweak.getKey(16)));
                            byte[] decoded = Base64.decode(json.getString(entry).getBytes(Charset.forName("UTF-8")), Base64.DEFAULT);
                            value = new String(aes.doFinal(decoded), Charset.forName("UTF-8"));
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unexpected exception. " + e.getMessage());
                        }
                    case "lat":
                        value = LAT.decrypt(json.getString(entry), key, tweak); break;
                    case "lon":
                        value = LON.decrypt(json.getString(entry), key, tweak); break;
                    case "tst":
                    case "wtst":
                        value = TST.decrypt(BigInteger.valueOf(json.getLong(entry)), key, tweak).longValue(); break;
                    default: //all other entries are not decrypted
                        value = json.get(entry); break;
                }
                decryptedJson.put(entry, value);
            }
            catch (JSONException e) {
                throw new RuntimeException("Unexpected exception. " + e.getMessage());
            }
        }
        return decryptedJson;
    }

}