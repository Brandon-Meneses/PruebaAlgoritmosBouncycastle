package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class AlgorithmChecker {

    public static void main(String[] args) {
        // Registrar BouncyCastle provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Verificar si SHA256withRSA está disponible
        checkAlgorithm("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);

        // Listar todos los algoritmos disponibles en BouncyCastle
        listAlgorithms(BouncyCastleProvider.PROVIDER_NAME);
    }

    public static void checkAlgorithm(String algorithm, String provider) {
        try {
            Signature.getInstance(algorithm, provider);
            System.out.println("Algorithm " + algorithm + " is available for provider " + provider + ".");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println("Algorithm " + algorithm + " is NOT available for provider " + provider + ".");
            e.printStackTrace();
        }
    }

    public static void listAlgorithms(String providerName) {
        Provider provider = Security.getProvider(providerName);
        if (provider != null) {
            System.out.println("Algorithms available for provider " + providerName + ":");
            for (Provider.Service service : provider.getServices()) {
                System.out.println(service.getType() + ": " + service.getAlgorithm());
            }
        } else {
            System.err.println("Provider " + providerName + " not found.");
        }
    }
}
