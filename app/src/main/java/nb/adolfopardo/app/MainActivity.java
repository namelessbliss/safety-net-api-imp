package nb.adolfopardo.app;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.nimbusds.jose.JWSObject;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

public class MainActivity extends AppCompatActivity {

    private TextView tvBasic, tvProfileMatch, tvDetail;
    private Button btnGet;

    private static final Random mRandom = new SecureRandom();

    private static String mResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvBasic = findViewById(R.id.tvBasic);
        tvProfileMatch = findViewById(R.id.tvProfileMatch);
        tvDetail = findViewById(R.id.tvDetail);
        btnGet = findViewById(R.id.btnGet);

        btnGet.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendSafetyNetRequest();
            }
        });
    }

    public void sendSafetyNetRequest() {
        try {
            String nonceData = "SafetyNetReq: " + System.currentTimeMillis();
            byte[] nonce = getRequestNonce(nonceData);

            SafetyNet.getClient(this).attest(nonce, "-----------AQUI VA EL API KEY------------")
                    .addOnSuccessListener((Activity) this,
                            new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                                @Override
                                public void onSuccess(SafetyNetApi.AttestationResponse response) {
                                    mResult = response.getJwsResult();
                                    Log.d("GoogleSafety", "SafetyNet result:\n" + mResult + "\n");

                                    try {
                                        //Convertir resultado a json
                                        final JWSObject jwsObject = JWSObject.parse(mResult);
                                        Log.d("GoogleSafety", "header =" + jwsObject.getHeader() + "\n");
                                        Log.d("GoogleSafety", "header =" + jwsObject.getHeader().getX509CertChain() + "\n");
                                        Log.d("GoogleSafety", "payload =\n" + jwsObject.getPayload().toJSONObject() + "\n");
                                        Log.d("GoogleSafety", "signature =" + jwsObject.getSignature() + "\n");
                                        Log.d("GoogleSafety", "signature =" + jwsObject.getSignature().decodeToString() + "\n");

                                        //Obtiene resultado convertido a json
                                        JSONObject json = new JSONObject(jwsObject.getPayload().toJSONObject());

                                        if (!json.isNull("basicIntegrity"))
                                            tvBasic.setText(json.getString("basicIntegrity"));

                                        if (!json.isNull("ctsProfileMatch"))
                                            tvProfileMatch.setText(json.getString("ctsProfileMatch"));

                                        if (!json.isNull("basicIntegrity") && !json.isNull("ctsProfileMatch")) {
                                            if ((Boolean) json.get("basicIntegrity") == true && (Boolean) json.get("ctsProfileMatch") == true)
                                                tvDetail.setText("Dispositivo certificado por Google");
                                            else if ((Boolean) json.get("basicIntegrity") == true && (Boolean) json.get("ctsProfileMatch") == false)
                                                tvDetail.setText("Detail: Dispositivo original pero no certificado");
                                            else if ((Boolean) json.get("basicIntegrity") == false && (Boolean) json.get("ctsProfileMatch").equals("true") == true)
                                                tvDetail.setText("Dispositivo no certificado sin integridad básica");
                                            else if ((Boolean) json.get("basicIntegrity") == false && (Boolean) json.get("basicIntegrity") == false)
                                                tvDetail.setText("Dudas en la integridad del sistema");
                                        }
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            })
                    .addOnFailureListener((Activity) this, new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            if (e instanceof ApiException) {
                                ApiException apiException = (ApiException) e;
                                Log.d("GoogleSafety", "Error: " + ((ApiException) e).getStatusCode());
                            }
                            Log.d("GoogleSafety", "Error: " + e.getMessage());
                        }
                    });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a 16-byte nonce with additional data.
     * The nonce should also include additional information, such as a user id or any other details
     * you wish to bind to this attestation. Here you can provide a String that is included in the
     * nonce after 24 random bytes. During verification, extract this data again and check it
     * against the request that was made with this nonce.
     */
    private static byte[] getRequestNonce(String data) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[24];
        mRandom.nextBytes(bytes);
        try {
            byteStream.write(bytes);
            byteStream.write(data.getBytes());
        } catch (IOException e) {
            return null;
        }

        return byteStream.toByteArray();
    }
}