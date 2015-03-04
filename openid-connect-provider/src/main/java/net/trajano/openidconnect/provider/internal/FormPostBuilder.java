package net.trajano.openidconnect.provider.internal;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class FormPostBuilder {

    private static final String TEMPLATE;

    private static final String INPUT_HIDDEN_FORMAT = "<input type='hidden' name='%1s' value='%2s' />";
    static {
        try {
            InputStream templateStream = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("META-INF/form_post.html");
            Scanner scanner = new Scanner(templateStream);
            TEMPLATE = scanner.useDelimiter("\\A")
                    .next();
            scanner.close();
            templateStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public FormPostBuilder(URI redirectUri) {

        this.redirectUri = redirectUri;
    }

    private final URI redirectUri;

    private final Map<String, String> inputMap = new HashMap<>();

    public String buildFormPost() {

        StringBuilder inputs = new StringBuilder();
        for (Map.Entry<String, String> entry : inputMap.entrySet()) {
            inputs.append(String.format(INPUT_HIDDEN_FORMAT, entry.getKey(), entry.getValue()));
        }
        return String.format(TEMPLATE, redirectUri, inputs);
    }

    public void put(String name,
            String value) {

            inputMap.put(name, value);
    }
}
