package net.trajano.openidconnect.crypto.test;

import java.util.Arrays;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;

import org.junit.Test;

public class AlgorithmTest {

    @Test
    public void getSigAlgorithms() {

        System.out.println(Arrays.asList(JsonWebAlgorithm.getSigAlgorithms()));
    }

    @Test
    public void getKexAlgorithms() {

        System.out.println(Arrays.asList(JsonWebAlgorithm.getKexAlgorithms()));
    }

    @Test
    public void getEncAlgorithms() {

        System.out.println(Arrays.asList(JsonWebAlgorithm.getEncAlgorithms()));
    }
}
