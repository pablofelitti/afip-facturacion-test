package ar.com.afip.service;

import org.junit.Test;

public class AfipServiceTest {

    @Test
    public void generar() throws Exception {
        System.out.println(new AfipService().generateLoginCMS());
    }
}
