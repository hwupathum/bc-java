package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsKyberDomain implements TlsPQCDomain
{
    public static KyberParameters getKyberParameters(TlsPQCConfig pqcConfig)
    {
        switch (pqcConfig.getPQCNamedGroup())
        {
        case NamedGroup.kyber512:
            return KyberParameters.kyber512;
        case NamedGroup.kyber768:
            return KyberParameters.kyber768;
        case NamedGroup.kyber1024:
            return KyberParameters.kyber1024;
        default:
            return null;
        }
    }

    protected final BcTlsCrypto crypto;
    protected final TlsPQCConfig pqcConfig;
    protected final KyberParameters kyberParameters;
    private final SHA3Digest sha3Digest256;
    private final SHAKEDigest shakeDigest;
    private static final int KyberSymBytes = 32;


    public TlsPQCConfig getTlsPQCConfig()
    {
        return pqcConfig;
    }

    public BcTlsKyberDomain(BcTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.crypto = crypto;
        this.pqcConfig = pqcConfig;
        this.kyberParameters = getKyberParameters(pqcConfig);
        this.shakeDigest = new SHAKEDigest(256);
        this.sha3Digest256 = new SHA3Digest(256);
    }

    public TlsAgreement createPQC()
    {
        return new BcTlsKyber(this);
    }

    public KyberPublicKeyParameters decodePublicKey(byte[] encoding)
    {
        return new KyberPublicKeyParameters(kyberParameters, encoding);
    }

    public byte[] encodePublicKey(KyberPublicKeyParameters kyberPublicKeyParameters)
    {
        return kyberPublicKeyParameters.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(crypto.getSecureRandom(), kyberParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public TlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public SecretWithEncapsulation enCap(KyberPublicKeyParameters peerPublicKey)
    {
        KyberKEMGenerator kemGen = new KyberKEMGenerator(crypto.getSecureRandom());
        SecretWithEncapsulation secretWithEncapsulation = kemGen.generateEncapsulated(peerPublicKey);
        byte[] outputSharedSecret = new byte[KyberSymBytes];
        byte[] kr = new byte[2*KyberSymBytes];
        System.arraycopy(secretWithEncapsulation.getEncapsulation(), 0, kr, 0, KyberSymBytes);
        hash_h(kr, secretWithEncapsulation.getSecret(), KyberSymBytes);
        kdf(outputSharedSecret, kr);
        return new SecretWithEncapsulationImpl(outputSharedSecret, secretWithEncapsulation.getEncapsulation());
    }

    public byte[] deCap(KyberPrivateKeyParameters kyberPrivateKeyParameters, byte[] cipherText)
    {
        KyberKEMExtractor kemExtract = new KyberKEMExtractor(kyberPrivateKeyParameters);
        byte[] secret = kemExtract.extractSecret(cipherText);
        byte[] outputSharedSecret = new byte[KyberSymBytes];
        byte[] kr = new byte[2*KyberSymBytes];
        System.arraycopy(secret, 0, kr, 0, KyberSymBytes);
        hash_h(kr, cipherText, KyberSymBytes);
        kdf(outputSharedSecret, kr);
        return outputSharedSecret;
    }

    private void kdf(byte[] out, byte[] in)
    {
        shakeDigest.update(in, 0, in.length);
        shakeDigest.doFinal(out, 0, out.length);
    }

    private void hash_h(byte[] out, byte[] in, int outOffset)
    {
        sha3Digest256.update(in, 0, in.length);
        sha3Digest256.doFinal(out, outOffset);
    }
}
