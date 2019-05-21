class RSAEcryptionSimulation {
    public static void main(String[] args) throws Exception {
        Machine sender = new Machine(11, 13);
        Machine receiver = new Machine(17, 23);

        receiver.RSAMakePublicKey();
        receiver.RSAMakePrivateKey();

        int msg = 11;
        int sendmsg = sender.RSAEncodeMsg(receiver.publicKey, msg);
        System.out.println("orginal message: " + msg);
        System.out.println("encrypted msg: " + sendmsg);

        int receivemsg = receiver.RSADecodeMsg(sendmsg);
        System.out.println("decrypted msg: " + receivemsg);
    }

}

class EncryptionHelper {

    // ***In Java, % returns remainder, not modulo
    public static int mod(int num, int modulus) {
        int rem = num % modulus;
        if (rem < 0) rem += modulus;
        return rem;
    }

    // ***In Java, % returns remainder, not modulo
    public static int mod(double num, int modulus) {
        int rem = (int) (num % modulus);
        if (rem < 0) rem += modulus;
        return rem;
    }

    // x^y mod N
    public static int modexp(int x, int y, int N) {
        if (y == 0) return 1;
        int z = modexp(x, y >> 1, N);

        int pow = (int) Math.pow(z, 2);
        if (mod(y, 2) == 0) {
            return mod(pow, N);
        } else {
            return mod(pow * x, N);
        }
    }

    // GCD
    // Euclid's rule - if a & b are positive integers, a >= b
    //                  then gcd(a, b) = gcd(a mod b, b)
    public static int euclid(int a, int b) {
        if (b == 0) return a;
        return euclid(b, mod(a, b));
    }

    // check if num is a prime number
    // if prime - return true
    public static boolean primality(int num) {
        for (int i=1; i<num; i++) {
            if (modexp(i, num-1,num) != 1) {
                return false;
            }
        }
        return true;
    }

    // Extended GCD
    // Lemma - if d divides both a and b, and d = ax + by for some x and y
    //          then d = gcd(a, b)
    // below method finds x and y
    public static int[] extendedEuclid(int a, int b) {
        // result[0] - x
        // result[1] - y
        // result[2] - GCD of a and b

        if (b == 0) {
            int[] result = {1, 0, a};
            return result;
        }

        int[] result = extendedEuclid(b, mod(a, b));
        int temp = result[0];
        result[0] = result[1];
        result[1] = temp - Math.floorDiv(a, b) * result[0];
        return result;
    }
}

class PublicKeyPair {
    int modulus;
    int encode;
}

class Machine {

    private int secret;
    private int p;
    private int q;

    public PublicKeyPair publicKey;

    public Machine(int setp, int setq) throws Exception {
        //first check p and q are both primes
        if (!EncryptionHelper.primality(p)) {
            throw new Exception("p not a prime number");
        }

        if (!EncryptionHelper.primality(q)) {
            throw new Exception("q not a prime number");
        }

        p = setp;
        q = setq;
    }

    public void RSAMakePublicKey() {
        // proceed to make public key pair
        this.publicKey = new PublicKeyPair();
        // first index is modulus
        // second index is the key

        //modulus
        this.publicKey.modulus = this.p*this.q;

        // key
        int keyCandidate = 3;
        while (EncryptionHelper.euclid(keyCandidate, (this.p-1)*(this.q-1)) != 1) keyCandidate++;
        this.publicKey.encode = keyCandidate;
    }

    public void RSAMakePrivateKey() {
        // result = [x, y, d] where ax + by = d calling extendedEuclid(a. b)
        int modulus = (this.p-1)*(this.q-1);
        int[] result = EncryptionHelper.extendedEuclid(this.publicKey.encode, modulus);

        this.secret = EncryptionHelper.mod(result[0], modulus);
    }

    public int RSAEncodeMsg(PublicKeyPair publicKey, int msg) throws Exception {
        if (publicKey == null) throw new Exception("cannot encode with empty public key");

        int encodedMsg =
                EncryptionHelper.modexp(msg, publicKey.encode, publicKey.modulus);
        return encodedMsg;
    }

    public int RSADecodeMsg(int msg) throws Exception {
        if (this.publicKey == null) throw new Exception("public key haven't been set");
        if (this.secret == 0) throw new Exception("private key haven't been set");

        int decodedMsg = EncryptionHelper.modexp(msg, this.secret, this.publicKey.modulus);
        return decodedMsg;
    }
}