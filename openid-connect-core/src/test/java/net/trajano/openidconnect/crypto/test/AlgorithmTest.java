package net.trajano.openidconnect.crypto.test;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;

import org.junit.Test;

public class AlgorithmTest {

    @Test
    public void getSigAlgorithms() {

        System.out.println(JsonWebAlgorithm.getSigAlgorithms());
    }

    @Test
    public void getKexAlgorithms() {

        System.out.println(JsonWebAlgorithm.getKexAlgorithms());
    }

    @Test
    public void getEncAlgorithms() {

        System.out.println(JsonWebAlgorithm.getEncAlgorithms());
    }
}
