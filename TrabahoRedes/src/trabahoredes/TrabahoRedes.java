package trabahoredes;

import exceptions.*;
import interfaces.*;
import java.io.File;

public class TrabahoRedes {

    public static void main(String[] args) throws ArquivoInexistente, ArgumentoInvalido {

        File path;
        boolean resumido = false;

        //Verifica se há parametrôs na chamada da função
        if (args.length > 0) {
            //Caso -r
            if (args.length == 2) {

                if (args[0].equals("-r")) {
                    resumido = true;
                    path = new File(args[1]);
                    if (!path.exists()) {
                        throw new ArquivoInexistente();
                    }
                } else {
                    throw new ArgumentoInvalido();
                }
            } else if (args.length == 1) {
                path = new File(args[0]);
                if (!path.exists()) {
                    throw new ArquivoInexistente();
                }
            }
        } else {
            new main().setVisible(true);
        }

    }
}
