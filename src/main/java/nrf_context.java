// Java translation of Go context package with post-quantum support only
// This version removes classical cryptography (RSA, ECC)

package context;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.coranlabs.nrf.logger.Logger;
import com.coranlabs.nrf.pkg.factory.Factory;
import com.lakshya_chopra.openapi.models.*;
import com.lakshya_chopra.openapi.oauth.OAuth;

public class NRFContext implements NFContext {
    public NfProfile nrfNfProfile = new NfProfile();
    public String nrfNfInstanceId;
    public Object rootPrivKey;
    public Object rootPubKey;
    public X509Certificate rootCert;
    public Object nrfPrivKey;
    public Object nrfPubKey;
    public X509Certificate nrfCert;
    public int nfRegistNum;
    private final ReentrantReadWriteLock nfRegistNumLock = new ReentrantReadWriteLock();

    public static final String NfProfileCollName = "NfProfile";

    private static final NRFContext nrfContext = new NRFContext();

    public static NRFContext getSelf() {
        return nrfContext;
    }

    public static void initNrfContext() throws Exception {
        var config = Factory.getNrfConfig();
        Logger.initLog.info("nrfconfig Info: Version[" + config.info.version + "] Description[" + config.info.description + "]");

        nrfContext.nrfNfProfile.setNfInstanceId(UUID.randomUUID().toString());
        nrfContext.nrfNfProfile.setNfType(NfType.NRF);
        nrfContext.nrfNfProfile.setNfStatus(NfStatus.REGISTERED);
        nrfContext.nfRegistNum = 0;

        List<String> serviceNameList = config.configuration.serviceNameList;

        if (config.getOAuth()) {
            String rootPrivKeyPath = config.getRootPrivKeyPath();
            String rootPubKeyPath = config.getRootCertPemPath();

            try {
                nrfContext.rootPrivKey = OAuth.parsePrivateKeyFromPEM(rootPrivKeyPath, true, "Ed448-Dilithium3");
            } catch (Exception e) {
                makeDir(rootPrivKeyPath);
                var keypair = OAuth.generateCirclKeypair(rootPubKeyPath, rootPrivKeyPath, "Ed448-Dilithium3");
                nrfContext.rootPubKey = keypair.getLeft();
                nrfContext.rootPrivKey = keypair.getRight();
            }

            String nrfPrivKeyPath = "nrf-oauth-priv.pem";
            String nrfPublicKeyPath = "nrf-oauth-pub.pem";

            var nrfKeypair = OAuth.generateCirclKeypair(nrfPublicKeyPath, nrfPrivKeyPath, "Ed448-Dilithium3");
            nrfContext.nrfPubKey = nrfKeypair.getLeft();
            nrfContext.nrfPrivKey = nrfKeypair.getRight();

            String nrfCertPath = config.getNrfCertPemPath();
            Logger.initLog.info("generated new NRF PQ cert: " + nrfCertPath);
        }

        var NFServices = initNFService(serviceNameList, config.info.version);
        nrfContext.nrfNfProfile.setNfServices(NFServices);
    }

    private static List<NfService> initNFService(List<String> srvNameList, String version) {
        String[] tmpVersion = version.split("\\.");
        String versionUri = "v" + tmpVersion[0];
        List<NfService> nfServices = new ArrayList<>();
        for (int i = 0; i < srvNameList.size(); i++) {
            ServiceName name = ServiceName.valueOf(srvNameList.get(i));
            NfService service = new NfService();
            service.setServiceInstanceId(Integer.toString(i));
            service.setServiceName(name);
            service.setVersions(List.of(new NfServiceVersion(version, versionUri)));
            service.setScheme(UriScheme.valueOf(Factory.getNrfConfig().getSbiScheme()));
            service.setNfServiceStatus(NfServiceStatus.REGISTERED);
            service.setApiPrefix(Factory.getNrfConfig().getSbiUri());
            service.setIpEndPoints(List.of(new IpEndPoint(
                Factory.getNrfConfig().getSbiRegisterIP(),
                TransportProtocol.TCP,
                Factory.getNrfConfig().getSbiPort()
            )));
            nfServices.add(service);
        }
        return nfServices;
    }

    private static void makeDir(String filePath) {
        java.io.File file = new java.io.File(filePath);
        java.io.File dir = file.getParentFile();
        if (dir != null && !dir.exists()) {
            dir.mkdirs();
        }
    }

    @Override
    public Exception authorizationCheck(String token, ServiceName serviceName) {
        if (!Factory.getNrfConfig().getOAuth()) {
            return null;
        }
        try {
            OAuth.verifyOAuth(token, serviceName.toString(), Factory.getNrfConfig().getNrfCertPemPath(), true, "Ed448-Dilithium3");
            return null;
        } catch (Exception e) {
            Logger.accTokenLog.warning("AuthorizationCheck: " + e);
            return e;
        }
    }

    public void addNfRegister() {
        nfRegistNumLock.writeLock().lock();
        try {
            nfRegistNum++;
        } finally {
            nfRegistNumLock.writeLock().unlock();
        }
    }

    public void delNfRegister() {
        nfRegistNumLock.writeLock().lock();
        try {
            nfRegistNum--;
        } finally {
            nfRegistNumLock.writeLock().unlock();
        }
    }
}

interface NFContext {
    Exception authorizationCheck(String token, ServiceName serviceName);
}
