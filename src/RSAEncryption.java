import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.swing.*;

public class RSAEncryption {
    //----------------CaesarEncrypt(method)----------------
    // Caesar 암호화 메서드. 각 문자를 shift 값만큼 이동시켜 암호화한다.
    public static String CaesarEncrypt(String text, int shift) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (Character.isUpperCase(c)) { // 대문자인 경우
                char encrypted = (char) ((c + shift - 'A') % 26 + 'A');
                result.append(encrypted);
            }
            else if (Character.isLowerCase(c)) { // 소문자인 경우
                char encrypted = (char) ((c + shift - 'a') % 26 + 'a');
                result.append(encrypted);
            }
            else { // 그 외의 문자는 그대로 유지
                result.append(c);
            }
        }
        return result.toString();
    }

    // Caesar 복호화 메서드. 암호화와 반대 방향으로 이동시켜 원래의 텍스트를 복원한다.
    public static String CaesarDecrypt(String text, int shift) {
        return CaesarEncrypt(text, 26 - shift); // 암호화와 반대 방향으로 이동
    }

    //----------------RSA 기법(method)----------------
    private final BigInteger n; // 공개 키 n
    private final BigInteger e; // 공개 키 지수 e
    private final BigInteger d; // 개인 키 d

    // RSA 생성자. 공개 키와 개인 키를 초기화한다.
    public RSAEncryption(BigInteger n, BigInteger e, BigInteger d) {
        this.n = n;
        this.e = e;
        this.d = d;
    }

    // RSA 암호화 메서드. 메시지를 공개 키 (e, n)로 암호화한다.
    public BigInteger RSAEncrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    // RSA 복호화 메서드. 암호문을 개인 키 (d, n)로 복호화한다.
    public BigInteger RSADecrypt(BigInteger cipher) {
        return cipher.modPow(d, n);
    }

    public static void main(String[] args) {
        //----------------Choose PopUpPage----------------
        // 암호화 기법 선택 팝업 창 생성
        String[] answer = {"1. Caesar", "2. RSA"};
        int ans = JOptionPane.showOptionDialog(null, "Choose the Encryption Technique you want to use", "기법 선택", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.INFORMATION_MESSAGE, null, answer, answer[0]);

        //----------------CaesarEncrypt(main)----------------
        // Caesar 암호화를 선택한 경우 실행
        if (ans == 0) {
            String CaesarMessageString = JOptionPane.showInputDialog("Write the sentence what you want to encode & decode");
            int shift = 5; // 기본 시프트 값 설정

            // 암호화 및 복호화 수행
            String encryptedText = CaesarEncrypt(CaesarMessageString, shift);
            String decryptedText = CaesarDecrypt(encryptedText, shift);

            // 결과 출력
            JOptionPane optionPane = new JOptionPane(
                    "Original Text: " + CaesarMessageString
                            + "\nEncrypted: " + encryptedText
                            + "\nDecrypted: " + decryptedText);
            JDialog dialog = optionPane.createDialog("Caear print");

            dialog.setResizable(true);
            dialog.setVisible(true);
        }

        //----------------RSA(main)----------------
        // RSA 암호화를 선택한 경우 실행
        if (ans == 1) {
            int bitLength = 1024; // 키 길이 설정
            SecureRandom secureRandom = new SecureRandom();

            // 두 개의 큰 소수 p, q 생성
            BigInteger p = BigInteger.probablePrime(bitLength / 2, secureRandom);
            BigInteger q = BigInteger.probablePrime(bitLength / 2, secureRandom);

            // n = p * q, 공개 키의 모듈러스
            BigInteger n = p.multiply(q);

            // 오일러의 토션트 함수 φ(n) 계산
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // 공개 지수 e 설정 (일반적으로 65537 사용)
            BigInteger e = BigInteger.valueOf(65537);

            // 개인 키 d 계산
            BigInteger d = e.modInverse(phi);

            // RSA 인스턴스 생성
            RSAEncryption rsa = new RSAEncryption(n, e, d);

            // 사용자 입력 수집
            String RSAMessageString = JOptionPane.showInputDialog("Write the sentence what you want to encode & decode");

            try {
                // 입력된 문자열을 UTF-8 바이트 배열로 변환
                byte[] messageBytes = RSAMessageString.getBytes(StandardCharsets.UTF_8);
                BigInteger message = new BigInteger(1, messageBytes);

                // 메시지를 암호화하여 암호문 생성
                BigInteger cipherText = rsa.RSAEncrypt(message);
                String cipherTextHex = cipherText.toString(16); // 16진수로 변환하여 가독성 증가

                // 암호문을 복호화하여 원래 메시지 복원
                BigInteger decryptedMessage = rsa.RSADecrypt(cipherText);
                byte[] decryptedBytes = decryptedMessage.toByteArray();

                // UTF-8 문자열로 변환
                if (decryptedBytes[0] == 0) { // 앞에 불필요한 0이 있는 경우 제거
                    byte[] tmp = new byte[decryptedBytes.length - 1];
                    System.arraycopy(decryptedBytes, 1, tmp, 0, tmp.length);
                    decryptedBytes = tmp;
                }

                String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

                // 결과 출력
                JTextArea textArea = new JTextArea(10, 30);
                textArea.setText(
                        "Public Key(n, e): " + n + ", " + e
                                + "\nPrivate Key(d): " + d
                                + "\nOriginal Text: " + RSAMessageString
                                + "\n\nEncrypted(Hex): " + cipherTextHex
                                + "\nDecrypted: " + decryptedString); // 긴 텍스트 예시
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);

                // JTextArea를 JScrollPane에 추가
                JScrollPane scrollPane = new JScrollPane(textArea);

                // JScrollPane을 포함한 JOptionPane 생성
                JOptionPane optionPane = new JOptionPane(scrollPane, JOptionPane.PLAIN_MESSAGE, JOptionPane.DEFAULT_OPTION);
                JDialog dialog = optionPane.createDialog("RSA print");

                dialog.setResizable(true);
                dialog.setVisible(true);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
            }
        }
        System.exit(0);
    }

}
