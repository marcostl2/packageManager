/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 *
 * @author sawada19941
 */
public class ArquivoInexistente extends Exception {

    public ArquivoInexistente() {
        super();
        System.err.println("Arquivo inexistente");
    }
}
