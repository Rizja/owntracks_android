package org.owntracks.android.activities;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.support.v7.app.ActionBarActivity;
import android.support.v7.widget.Toolbar;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.util.SparseBooleanArray;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;

import com.afollestad.materialdialogs.MaterialDialog;
import com.mikepenz.materialdrawer.Drawer;
import com.mikepenz.materialdrawer.model.interfaces.IDrawerItem;
import com.rengwuxian.materialedittext.MaterialEditText;

import de.greenrobot.event.EventBus;

import org.owntracks.android.R;
import org.owntracks.android.services.ServiceBroker;
import org.owntracks.android.services.ServiceProxy;
import org.owntracks.android.support.ConnectionToolbarPreference;
import org.owntracks.android.support.DrawerFactory;
import org.owntracks.android.support.Events;
import org.owntracks.android.support.FormatPreservingEncryption;
import org.owntracks.android.support.Preferences;

import java.util.ArrayList;
import java.util.Arrays;

public class ActivityPreferences extends ActionBarActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final Context context = this;


        setContentView(R.layout.activity_preferences);
        Toolbar toolbar = (Toolbar) findViewById(R.id.fragmentToolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setTitle(getTitle());
        getSupportActionBar().setDisplayShowHomeEnabled(true);

        Drawer.OnDrawerItemClickListener drawerListener = new Drawer.OnDrawerItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id, IDrawerItem drawerItem) {
                switch (drawerItem.getIdentifier()) {
                    case R.string.idLocations:
                        goToRoot();
                        break;
                    case R.string.idWaypoints:
                        Intent intent = new Intent(context, ActivityWaypoints.class);
                        startActivity(intent);
                        break;
                    case R.string.idSettings:
                        break;
                }
            }
        };

        DrawerFactory.buildDrawer(this, toolbar, drawerListener, 2);
        getFragmentManager().beginTransaction().replace(R.id.content_frame, new FragmentPreferences()).commit();

    }


    private void goToRoot() {
        Intent intent1 = new Intent(this, ActivityMain.class);
        intent1.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(intent1);
        finish();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:     // If the user hits the toolbar back arrow, go back to ActivityMain, no matter where he came from (same as hitting back)
                goToRoot();
                return true;
            case R.id.connect:

                Runnable r = new Runnable() {

                    @Override
                    public void run() {
                        ServiceProxy.getServiceBroker().reconnect();
                    }
                };
                new Thread(r).start();

                return true;
            case R.id.disconnect:
                Runnable s = new Runnable() {

                    @Override
                    public void run() {
                        ServiceProxy.getServiceBroker().disconnect(true);

                    }
                };
                new Thread(s).start();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }

    }

    // If the user hits back, go back to ActivityMain, no matter where he came from
    @Override
    public void onBackPressed() {
        goToRoot();
    }


    public static class FragmentPreferences extends PreferenceFragment {

        private static ConnectionToolbarPreference serverPreferenceToolbar;

        private static Preference hostPreference;
        private static Preference identificationPreference;
        private static Preference securityPreference;
        private static Preference optionsPreference;

        private static org.owntracks.android.support.EditStringPreference pubTopicBase;
        private static org.owntracks.android.support.EditIntegerPreference pubInterval;
        private static org.owntracks.android.support.EditStringPreference subTopic;
        private static org.owntracks.android.support.EditIntegerPreference locatorDisplacement;
        private static org.owntracks.android.support.EditIntegerPreference locatorInterval;
        private static org.owntracks.android.support.EditIntegerPreference beaconForegroundScanPeriod;
        private static org.owntracks.android.support.EditIntegerPreference beaconBackgroundScanPeriod;

        private static Preference version;
        private static Preference repo;
        private static Preference mail;
        private static Preference twitter;


        static String ver;
        private static SharedPreferences.OnSharedPreferenceChangeListener pubTopicListener;
        private static boolean tlsVal;
        private static boolean encVal;
        private static boolean cleansessionVal;
        private static boolean authenticationVal;




        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.preferences);
            final Activity a = getActivity();
            PackageManager pm = a.getPackageManager();

            repo = findPreference("repo");
            mail = findPreference("mail");
            twitter = findPreference("twitter");
            version = findPreference("versionReadOnly");
            serverPreferenceToolbar = (ConnectionToolbarPreference)findPreference("brokerPreference");
            pubInterval = (org.owntracks.android.support.EditIntegerPreference) findPreference(Preferences.getKey(R.string.keyPubInterval));
            pubInterval.setHint(Integer.toString(Preferences.getIntResource(R.integer.valPubInterval)));

            pubTopicBase = (org.owntracks.android.support.EditStringPreference) findPreference(Preferences.getKey(R.string.keyPubTopicBase));
            setPubTopicHint();

            subTopic = (org.owntracks.android.support.EditStringPreference) findPreference(Preferences.getKey(R.string.keySubTopic));
            subTopic.setHint(Preferences.getStringRessource(R.string.valSubTopic));

            locatorDisplacement = (org.owntracks.android.support.EditIntegerPreference) findPreference(Preferences.getKey(R.string.keyLocatorDisplacement));
            locatorDisplacement.setHint(Integer.toString(Preferences.getIntResource(R.integer.valLocatorDisplacement)));

            locatorInterval = (org.owntracks.android.support.EditIntegerPreference) findPreference(Preferences.getKey(R.string.keyLocatorInterval));
            locatorInterval.setHint(Integer.toString(Preferences.getIntResource(R.integer.valLocatorInterval)));

            beaconForegroundScanPeriod = (org.owntracks.android.support.EditIntegerPreference) findPreference(Preferences.getKey(R.string.keyBeaconForegroundScanPeriod));
            beaconForegroundScanPeriod.setHint(Integer.toString(Preferences.getIntResource(R.integer.valBeaconForegroundScanPeriod)));

            beaconBackgroundScanPeriod = (org.owntracks.android.support.EditIntegerPreference) findPreference(Preferences.getKey(R.string.keyBeaconBackgroundScanPeriod));
            beaconBackgroundScanPeriod.setHint(Integer.toString(Preferences.getIntResource(R.integer.valBeaconBackgroundScanPeriod)));

            hostPreference = findPreference(getString(R.string.keyHost));
            identificationPreference = findPreference(getString(R.string.keyIdentification));
            securityPreference = findPreference(getString(R.string.keySecurity));
            optionsPreference = findPreference(getString(R.string.keyOptions));


            try {
                ver = pm.getPackageInfo(a.getPackageName(), 0).versionName;
            } catch (PackageManager.NameNotFoundException e) {
                ver = a.getString(R.string.na);
            }
            version.setSummary(ver);


            pubInterval.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
                @Override
                public boolean onPreferenceChange(
                        Preference preference, Object newValue) {
                    Log.v("ActivityPreferences", newValue.toString());
                    if (newValue.toString().equals("0")) {
                        SharedPreferences.Editor editor = PreferenceManager.getDefaultSharedPreferences(a).edit();
                        editor.putString(preference.getKey(), "1");
                        editor.commit();
                        return false;
                    }
                    return true;
                }
            });


            repo.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    intent.setData(Uri.parse(Preferences.getRepoUrl()));
                    a.startActivity(intent);
                    return false;
                }
            });

            mail.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    Intent intent = new Intent(Intent.ACTION_SEND);
                    intent.setType("message/rfc822");
                    intent.putExtra(Intent.EXTRA_EMAIL, new String[]{Preferences.getIssuesMail()});
                    intent.putExtra(Intent.EXTRA_SUBJECT, "OwnTracks (Version: " + ver + ")");
                    a.startActivity(Intent.createChooser(intent, "Send Email"));
                    return false;
                }
            });

            twitter.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    intent.setData(Uri.parse(Preferences.getTwitterUrl()));
                    a.startActivity(intent);
                    return false;
                }
            });

            setServerPreferenceSummary(this);

            // Sets the pubTopic hint value when username or deviceId changes
            pubTopicListener = new SharedPreferences.OnSharedPreferenceChangeListener() {

                @Override
                public void onSharedPreferenceChanged(
                        SharedPreferences sharedPreferences, String key) {
                    if (key.equals(Preferences.getKey(R.string.keyUsername)) || key.equals(Preferences.getKey(R.string.keyDeviceId))) {
                        setPubTopicHint();
                    }
                }
            };
            PreferenceManager.getDefaultSharedPreferences(a).registerOnSharedPreferenceChangeListener(pubTopicListener);

            hostPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    MaterialDialog dialog = new MaterialDialog.Builder(a)
                            .customView(R.layout.preferences_host, true)
                            .title(R.string.preferencesHost)
                            .positiveText(R.string.accept)
                            .negativeText(R.string.cancel)
                            .showListener(new DialogInterface.OnShowListener() {
                                @Override
                                public void onShow(DialogInterface dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    final MaterialEditText host = (MaterialEditText) d.findViewById(R.id.host);
                                    final MaterialEditText port = (MaterialEditText) d.findViewById(R.id.port);

                                    host.setText("" + Preferences.getHost(false));
                                    host.setFloatingLabelAlwaysShown(true);

                                    port.setText(Preferences.getPortSupportingHint());
                                    port.setFloatingLabelAlwaysShown(true);

                                }
                            })
                            .callback(new MaterialDialog.ButtonCallback() {
                                @Override
                                public void onPositive(MaterialDialog dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    final MaterialEditText host = (MaterialEditText) d.findViewById(R.id.host);
                                    final MaterialEditText port = (MaterialEditText) d.findViewById(R.id.port);

                                    Preferences.setHost(host.getText().toString());
                                    try {
                                        Preferences.setPort(Integer.parseInt(port.getText().toString()));
                                    } catch (NumberFormatException e) {
                                        Preferences.clearKey(R.string.keyPort);
                                    }
                                }
                            })

                            .show();

                    return true;
                }
            });


            authenticationVal = Preferences.getAuth();

            identificationPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    new MaterialDialog.Builder(a)
                            .customView(R.layout.preferences_identification, true)
                            .title(R.string.preferencesIdentification)
                            .positiveText(R.string.accept)
                            .negativeText(R.string.cancel)
                            .showListener(new DialogInterface.OnShowListener() {
                                @Override
                                public void onShow(DialogInterface dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    Switch authentication = (Switch) d.findViewById(R.id.authentication);
                                    final MaterialEditText username = (MaterialEditText) d.findViewById(R.id.username);
                                    final MaterialEditText password = (MaterialEditText) d.findViewById(R.id.password);
                                    final MaterialEditText deviceId = (MaterialEditText) d.findViewById(R.id.deviceId);
                                    final MaterialEditText trackerId = (MaterialEditText) d.findViewById(R.id.trackerId);
                                    final MaterialEditText clientId = (MaterialEditText) d.findViewById(R.id.clientId);


                                    authentication.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                        @Override
                                        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                            authenticationVal = isChecked;
                                            password.setVisibility(authenticationVal ? View.VISIBLE : View.GONE);
                                        }
                                    });

                                    username.addTextChangedListener(new TextWatcher() {
                                        @Override
                                        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                                        }

                                        @Override
                                        public void onTextChanged(CharSequence s, int start, int before, int count) {
                                        }

                                        @Override
                                        public void afterTextChanged(Editable s) {
                                            clientId.setHint(Preferences.getTmpClientIdFallback(username.getText().toString(), deviceId.getText().toString()));

                                        }
                                    });

                                    deviceId.addTextChangedListener(new TextWatcher() {
                                        @Override
                                        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                                        }

                                        @Override
                                        public void onTextChanged(CharSequence s, int start, int before, int count) {
                                        }

                                        @Override
                                        public void afterTextChanged(Editable s) {
                                            clientId.setHint(Preferences.getTmpClientIdFallback(username.getText().toString(), deviceId.getText().toString()));
                                            trackerId.setHint(Preferences.getTmpTrackerIdFallback(deviceId.getText().toString()));
                                        }
                                    });

                                    authentication.setChecked(authenticationVal);
                                    username.setText(Preferences.getUsername());
                                    password.setText(Preferences.getPassword());
                                    password.setVisibility(authenticationVal ? View.VISIBLE : View.GONE);
                                    deviceId.setHint(Preferences.getDeviceIdFallback());
                                    deviceId.setText(Preferences.getDeviceId(false));
                                    clientId.setHint(Preferences.getTmpClientIdFallback(username.getText().toString(), deviceId.getText().toString()));
                                    clientId.setText(Preferences.getClientId(false));
                                    trackerId.setText(Preferences.getTrackerId(false));
                                    trackerId.setHint(Preferences.getTmpTrackerIdFallback(deviceId.getText().toString()));

                                }
                            })
                            .callback(new MaterialDialog.ButtonCallback() {
                                @Override
                                public void onPositive(MaterialDialog dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    final MaterialEditText username = (MaterialEditText) d.findViewById(R.id.username);
                                    final MaterialEditText password = (MaterialEditText) d.findViewById(R.id.password);
                                    final MaterialEditText deviceId = (MaterialEditText) d.findViewById(R.id.deviceId);
                                    final MaterialEditText trackerId = (MaterialEditText) d.findViewById(R.id.trackerId);
                                    final MaterialEditText clientId = (MaterialEditText) d.findViewById(R.id.clientId);

                                    Preferences.setAuth(authenticationVal);
                                    Preferences.setUsername(username.getText().toString());
                                    Preferences.setPassword(password.getText().toString());
                                    Preferences.setDeviceId(deviceId.getText().toString());
                                    Preferences.setClientId(clientId.getText().toString());
                                    Preferences.setTrackerId(trackerId.getText().toString());

                                    serverPreferenceToolbar.conditionallyEnableConnectButton();

                                }
                            })

                            .show();

                    return true;
                }
            });

            tlsVal = Preferences.getTls();
            encVal =  Preferences.getEnc();
            securityPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    new MaterialDialog.Builder(a)
                            .customView(R.layout.preferences_security, true)
                            .title(R.string.preferencesSecurity)
                            .positiveText(R.string.accept)
                            .negativeText(R.string.cancel)
                            .showListener(new DialogInterface.OnShowListener() {
                                @Override
                                public void onShow(DialogInterface dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    Switch tls = (Switch) d.findViewById(R.id.tls);
                                    final MaterialEditText tlsCrt = (MaterialEditText) d.findViewById(R.id.tlsCrt);
                                    tls.setChecked(tlsVal);
                                    tlsCrt.setVisibility(tlsVal ? View.VISIBLE : View.GONE);
                                    tlsCrt.setText(Preferences.getTlsCrtPath());

                                    tls.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                        @Override
                                        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                            tlsVal = isChecked;
                                            tlsCrt.setVisibility(tlsVal ? View.VISIBLE : View.GONE);
                                        }
                                    });


                                    // Encryption
                                    final Switch enc = (Switch) d.findViewById(R.id.fpeEncryption);
                                    enc.setChecked(encVal);
                                    enc.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                        @Override
                                        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                            encVal = isChecked;

                                            if (encVal) { //encryption enabled
                                                final EditText input = new EditText(a);
                                                input.setInputType(input.getInputType()
                                                        | EditorInfo.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                                                        | EditorInfo.TYPE_TEXT_VARIATION_FILTER);

                                                new AlertDialog.Builder(a)
                                                        .setTitle("Password")
                                                        .setMessage("Enter a password for the encryption:")
                                                        .setView(input)
                                                        .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                                                            public void onClick(DialogInterface dialog, int whichButton) {
                                                                String fpePassword = input.getText().toString();
                                                                if (fpePassword.isEmpty()) //if no password is entered, disable encryption
                                                                    enc.setChecked(false);
                                                                else {
                                                                    FormatPreservingEncryption.setPassword(Preferences.getUsername(), fpePassword);

                                                                }
                                                            }
                                                        })
                                                        .setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                                                            public void onClick(DialogInterface dialog, int whichButton) {
                                                                enc.setChecked(false); //if password entry is cancelled, disable encryption
                                                            }
                                                        }).show();
                                            } else {
                                                FormatPreservingEncryption.deletePassword(Preferences.getUsername());
                                            }
                                        }
                                    });


                                    //Manage User / Passwords
                                    final TextView manageUser = (TextView) d.findViewById(R.id.manageUser);
                                    manageUser.setOnClickListener(new View.OnClickListener() {

                                        @Override
                                        public void onClick(View v) {
                                            final Dialog dialog = new Dialog(a);
                                            dialog.setContentView(R.layout.preferences_security_userlist);
                                            dialog.setTitle("User with stored passwords");
                                            final ListView userList = (ListView) dialog.findViewById(R.id.lstUser);

                                            //Load User-List
                                            final ArrayAdapter<String> adapter = new ArrayAdapter<String>(a, android.R.layout.simple_list_item_multiple_choice, new ArrayList<String>(Arrays.asList(FormatPreservingEncryption.loadUsers())));
                                            adapter.remove(Preferences.getUsername());
                                            if (adapter != null) userList.setAdapter(adapter);


                                            //Add-Button
                                            final Button btnAdd = (Button) dialog.findViewById(R.id.btnAdd);
                                            btnAdd.setOnClickListener(new View.OnClickListener() {

                                                @Override
                                                public void onClick(View v) {
                                                    LinearLayout lila1 = new LinearLayout(a);
                                                    lila1.setOrientation(LinearLayout.VERTICAL);
                                                    final EditText inputName = new EditText(a);
                                                    final EditText inputPW = new EditText(a);
                                                    inputPW.setInputType(inputPW.getInputType()
                                                            | EditorInfo.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                                                            | EditorInfo.TYPE_TEXT_VARIATION_FILTER);
                                                    inputName.setHint("Username");
                                                    inputPW.setHint("Password");
                                                    lila1.addView(inputName);
                                                    lila1.addView(inputPW);


                                                    new AlertDialog.Builder(a)
                                                            .setTitle("Add new User")
                                                            .setMessage("Enter username and password to decrypt location of this user:")
                                                            .setView(lila1)
                                                            .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                                                                public void onClick(DialogInterface dialog, int whichButton) {
                                                                    String username = inputName.getText().toString();
                                                                    String password = inputPW.getText().toString();

                                                                    if (!username.isEmpty() && !password.isEmpty()) {
                                                                        username = username.trim();
                                                                        FormatPreservingEncryption.setPassword(username, password);
                                                                        adapter.clear();
                                                                        adapter.addAll(Arrays.asList(FormatPreservingEncryption.loadUsers()));
                                                                        adapter.remove(Preferences.getUsername());
                                                                        new AlertDialog.Builder(a)
                                                                                .setTitle("Add")
                                                                                .setMessage("New user " + username + " successfully added")
                                                                                .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                                                                                    public void onClick(DialogInterface dialog, int whichButton) {
                                                                                    }
                                                                                }).show();
                                                                    } else {
                                                                        new AlertDialog.Builder(a)
                                                                                .setTitle("Add")
                                                                                .setMessage("Username and password must not be empty.")
                                                                                .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                                                                                    public void onClick(DialogInterface dialog, int whichButton) {
                                                                                    }
                                                                                }).show();
                                                                    }
                                                                }
                                                            })
                                                            .setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                                                                public void onClick(DialogInterface dialog, int whichButton) {
                                                                }
                                                            }).show();
                                                }
                                            });


                                            //Delete-Button
                                            final Button btnDelete = (Button) dialog.findViewById(R.id.btnDelete);
                                            btnDelete.setOnClickListener(new View.OnClickListener() {

                                                @Override
                                                public void onClick(View v) {
                                                    SparseBooleanArray checked = userList.getCheckedItemPositions();
                                                    ArrayAdapter adapter = (ArrayAdapter) userList.getAdapter();
                                                    for (int i = 0; i < userList.getCount(); i++) {
                                                        if (checked.get(i)) {
                                                            if (!adapter.getItem(i).equals(Preferences.getUsername())) { //don't delete own user
                                                                FormatPreservingEncryption.deletePassword(adapter.getItem(i).toString());
                                                            }
                                                        }
                                                    }
                                                    adapter.clear();
                                                    adapter.addAll(Arrays.asList(FormatPreservingEncryption.loadUsers()));
                                                    adapter.remove(Preferences.getUsername());
                                                    adapter.notifyDataSetChanged();
                                                    new AlertDialog.Builder(a)
                                                            .setTitle("Delete")
                                                            .setMessage("All selected entries have been deleted.")
                                                            .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                                                                public void onClick(DialogInterface dialog, int whichButton) {
                                                                }
                                                            }).show();
                                                }

                                            });

                                            dialog.show();

                                        }

                                    });


                                }
                            })
                            .callback(new MaterialDialog.ButtonCallback() {
                                @Override
                                public void onPositive(MaterialDialog dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    MaterialEditText tlsCrt = (MaterialEditText) d.findViewById(R.id.tlsCrt);
                                    Preferences.setEnc(encVal);
                                    Preferences.setTls(tlsVal);
                                    Preferences.setTlsCrtPath(tlsCrt.getText().toString());
                                    serverPreferenceToolbar.conditionallyEnableConnectButton();
                                }
                            })
                            .show();

                    return true;
                }
            });

            cleansessionVal = Preferences.getCleanSession();
            optionsPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    new MaterialDialog.Builder(a)
                            .customView(R.layout.preferences_options, true)
                            .title(R.string.preferencesOptions)
                            .positiveText(R.string.accept)
                            .negativeText(R.string.cancel)
                            .showListener(new DialogInterface.OnShowListener() {
                                @Override
                                public void onShow(DialogInterface dialog) {
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    Switch cleansession = (Switch) d.findViewById(R.id.cleanSession);
                                    final MaterialEditText keepalive = (MaterialEditText) d.findViewById(R.id.keepalive);
                                    cleansession.setChecked(cleansessionVal);
                                    cleansession.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                        @Override
                                        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                            cleansessionVal = isChecked;
                                        }
                                    });

                                    keepalive.setText(Preferences.getKeepaliveSupportingHint());

                                }
                            })
                            .callback(new MaterialDialog.ButtonCallback() {
                                @Override
                                public void onPositive(MaterialDialog dialog) {
                                    Log.v(this.toString(), "saving parameters");
                                    MaterialDialog d = MaterialDialog.class.cast(dialog);
                                    final MaterialEditText keepalive = (MaterialEditText) d.findViewById(R.id.keepalive);

                                    Preferences.setCleanSession(cleansessionVal);
                                    try {
                                        Preferences.setKeepalive(Integer.parseInt(keepalive.getText().toString()));

                                    } catch (NumberFormatException e) {
                                        Preferences.clearKey(R.string.keyKeepalive);
                                    }

                                    serverPreferenceToolbar.conditionallyEnableConnectButton();

                                }
                            })
                            .show();

                    return true;
                }
            });
        }

        @Override
        public void onStart() {
            super.onStart();
            EventBus.getDefault().registerSticky(this);

        }

        @Override
        public void onStop() {

            EventBus.getDefault().unregister(this);
            super.onStop();
        }

        @Override
        public void onDestroy() {
            if (pubTopicListener != null)
                PreferenceManager.getDefaultSharedPreferences(getActivity()).unregisterOnSharedPreferenceChangeListener(pubTopicListener);
            super.onDestroy();
        }

        public void onEventMainThread(Events.StateChanged.ServiceBroker e) {
            if ((e != null) && (e.getExtra() != null) && (e.getExtra() instanceof Exception)) {
                if ((((Exception) e.getExtra()).getCause() != null))
                    setServerPreferenceSummary(this, getResources().getString(R.string.error) + ": " + ((Exception) e.getExtra()).getCause().getLocalizedMessage());
                else
                    setServerPreferenceSummary(this, getResources().getString(R.string.error) + ": " + e.getExtra().toString());

            } else {
                setServerPreferenceSummary(this);
            }
        }

        private static void setServerPreferenceSummary(PreferenceFragment c) {
            setServerPreferenceSummary(c, ServiceBroker.getStateAsString(c.getActivity()));
        }

        private static void setServerPreferenceSummary(PreferenceFragment f, String s) {
            f.findPreference("brokerPreferenceScreen").setSummary(s);
            ((BaseAdapter) ((PreferenceScreen)f.findPreference("root")).getRootAdapter()).notifyDataSetChanged(); //Have to redraw the list to reflect summary change
        }

        private static void setPubTopicHint() {
            pubTopicBase.setHint(Preferences.getPubTopicFallback());
        }

      }
}


