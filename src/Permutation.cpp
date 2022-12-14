/*
 *  THIMBLE --- Research Libary for Development and Analysis of
 *  Fingerprint-Based Biometric Cryptosystems.
 *
 *  Copyright 2014 Benjamin Tams
 *
 *  THIMBLE is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation, either version 3 of
 *  the License, or (at your option) any later version.
 *
 *  THIMBLE is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with THIMBLE. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file Permutation.cpp
 *
 * @brief
 *            Implementation of a class for representation of and computation
 *            with permutations.
 *
 * @author Benjamin Tams
 */

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

#include <thimble/math/MathTools.h>
#include <thimble/math/Permutation.h>

using namespace std;

/**
 * @brief The library's namespace.
 */
namespace thimble {

    /**
     * @brief
     *            Prepares this permutation to encode a permutation of
     *            dimension <i>n</i>
     *
     * @details
     *            A call of this function causes 1) the field
     *            \link data\endlink to be freed and 2) to be allocated
     *            via <code>malloc</code> to hold <i>n</i> integers of
     *            type <code>int</code> or set to <code>NULL</code> if
     *            <i>n==0</i>. The content of \link data\endlink is not
     *            set to encode a valid permutation; this must be ensured
     *            by the programmer for which reason this method is
     *            declared private.
     *
     *            Furthermore, the argument <i>n</i> must be greater than
     *            or equals 0; otherwise, the program runs into
     *            undocumented behaviour.
     *
     * @param n
     *            The dimension/number of elements on which this
     *            permutation is prepared to operate.
     */
    void Permutation::prepareDim( int n ) {

        if ( this->n != n ) {

            free(this->data);
            this->data = NULL;
            this->n = n;

            if ( n != 0 ) {
                this->data = (int*)malloc( n * sizeof(int) );
                if ( this->data == NULL ) {
                    if ( this->data == NULL ) {
                        cerr << "Permutation: out of memory." << endl;
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
    }

    /**
     * @brief
     *            Creates the identity permutation to operate on an
     *            <i>n</i> elements.
     *
     * @param n
     *            The number of elements on which this permutation
     *            operates.
     *
     * @warning
     *            If <i>n</i> is negative, an error message is printed
     *            to <code>stderr</code> and the program exits with
     *            status 'EXIT_FAILURE'.
     *
     * @warning
     *            If not enough memory could be provided, an error
     *            message is printed to <code>stderr</code> and the
     *            program exits with status 'EXIT_FAILURE'.
     */
	Permutation::Permutation( int n ) {

        // Empty permutation and then,...
		this->n    = 0;
		this->data = NULL;

        // ... set the dimension which causes the permutation to become
        // the identity.
        setDimension(n);
	}

    /**
     * @brief
     *            Copy constructor.
     *
     * @details
     *            Creates a copy of the specified permutation.
     *
     * @param P
     *            The permutation of which a copy is created.
     *
     * @warning
     *            If not enough memory could be provided, an error
     *            message is printed to <code>stderr</code> and the
     *            program exits with status 'EXIT_FAILURE'.
     */
    Permutation::Permutation( const Permutation & P ) {
        // Empty permutation and then, ...
		this->n    = 0;
		this->data = NULL;
        // ... assignment.
        *this = P;
	}
    /**
     * @brief
     *            Destructor.
     *
     * @details
     *            Frees the data that has been allocated to encode this
     *            permutation.
     */
	Permutation::~Permutation() {
		free(this->data);
	}

    /**
     * @brief
     *            Assignment operator.
     *
     * @details
     *            Assigns this permutation to a copy of <i>P</i>.
     *
     * @param P
     *            The permutation of which this instance is assigned a
     *            copy of.
     *
     * @return
     *            A reference to this instance (after assignment).
     *
     * @warning
     *            If not enough memory could be provided, an error
     *            message is printed to <code>stderr</code> and the
     *            program exits with status 'EXIT_FAILURE'.
     */
    Permutation & Permutation::operator=( const Permutation & P ) {

        if ( this != &P ) {

            prepareDim(P.n);

            memcpy( this->data , P.data , P.n * sizeof(int) );
            this->n = P.n;
		}

		return *this;
	}

    /**
     * @brief
     *            Sets this instance to represent the identity permutation
     *            operating on <i>n</i> elements.
     *
     * @param n
     *            The number of elements on which this permutation
     *            operates.
     *
     * @warning
     *            If <i>n</i> is negative, an error message is printed
     *            to <code>stderr</code> and the program exits with status
     *            'EXIT_FAILURE'.
     *
     * @warning
     *            If not enough memory could be provided, an error
     *            message is printed to <code>stderr</code> and the
     *            program exits with status 'EXIT_FAILURE'.
     */
    void Permutation::setDimension( int n ) {

		if ( n < 0 ) {
            cerr << "Permutation::setLength: dimension must be positive."
                 << endl;
			exit(EXIT_FAILURE);
		}

        prepareDim(n);

        // Make the permutation the identity
		for ( int x = 0 ; x < n ; x++ ) {
			this->data[x] = x;
		}
	}

    /**
     * @brief
     *           Evaluates this permutation on the specified index.
     *
     * @details
     *           Write \f$\pi:\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$ as
     *           the permutation represented by this instance. The function
     *           returns \f$\pi(x)\f$.
     *
     * @param x
     *           The index at which this permutation is evaluated.
     *
     * @return
     *           The evaluation of this permutation at <i>x</i>.
     *
     * @warning
     *           If <i>x</i> is negative or greater than or equals
     *           \link getDimension()\endlink, an error message is printed
     *           to <code>stderr</code> and the program exits with status
     *           'EXIT_FAILURE'.
     */
	int Permutation::eval( int x ) const {

		if ( x < 0 || x >= this->n ) {
            // Permutation::eval: invalid argument
            throw 1;
		}

		return this->data[x];
	}

    /**
     * @brief
     *           Exchanges the evaluations of this permutation for the
     *           specified arguments.
     *
     * @details
     *           Let \f$\pi:\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$ be
     *           the permutation represented by this instance. The method
     *           replaces this permutation by the permutation
     *           \f$\pi':\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$ where
     *           \f$\pi'(x_0)=\pi(x_1)\f$, \f$\pi'(x_1)=\pi(x_0)\f$ and
     *           if \f$x\neq x_0,x_1\f$, then \f$\pi'(x)=\pi(x)\f$.
     *
     * @param x0
     *           First argument.
     *
     * @param x1
     *           Second argument.
     *
     * @warning
     *           If one of the arguments is negative or greater than or
     *           equals \link getDimension()\endlink, an error message
     *           is printed to <code>stderr</code> and the program exits
     *           with status 'EXIT_FAILURE'.
     */
    void Permutation::exchange( int x0 , int x1 ) {

		int y0 , y1;

        // Causes error message and exits if evaluation are performed
        // with invalid arguments.
		y0 = eval(x0);
		y1 = eval(x1);

		this->data[x0] = y1;
		this->data[x1] = y0;
	}

    /**
     * @brief
     *           Replaces this permutation by a random permutation of
     *           operating on the same number of elements.
     *
     * @param tryRandom
     *           If <code>true</code>, the method uses a cryptographic
     *           number generator if available on the system; otherwise,
     *           the method wraps around the standard <code>rand()</code>
     *           function.
     */
    void Permutation::random( bool tryRandom ) {

        int n = getDimension();

        for ( int i = 0 ; i < n ; i++ ) {
            int j = MathTools::rand32(tryRandom) % (uint32_t)n;
            exchange(i,j);
        }
    }

    /**
     * @brief
     *           Swaps the content of two permutations such that the one
     *           encodes the other.
     *
     * @param P
     *           First permutation.
     *
     * @param Q
     *           Second permutation.
     */
    void Permutation::swap( Permutation & P , Permutation & Q ) {

        int n;
        int *data;

        n = P.n;
        data = P.data;

        P.n = Q.n;
        P.data = Q.data;

        Q.n = n;
        Q.data = data;
    }

    /**
     * @brief
     *           Computes the concatenation of two permutations.
     *
     * @details
     *           More precisely, let
     *           \f$P,Q:\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$ be the
     *           two permutations of which the concatenation is to be
     *           computed. The method computes \f$R=P\circ Q\f$ which is
     *           the permutation that maps \f$x\f$ to \f$P(Q(x))\f$.
     *
     *           Consider the permutations \f$P\f$ and \f$Q\f$ as
     *           the matrices
     *           \f[
     *            A=(a_{i,j})_{i,j=0,...,n-1}
     *           \f]
     *           and
     *           \f[
     *            B=(b_{i,j})_{i,j=0,...,n-1},
     *           \f]
     *           respectively, where \f$a_{i,j}=1\f$ if \f$P(i)=j\f$ and
     *           \f$a_{i,j}=0\f$ otherwise and \f$b_{i,j}=1\f$ if
     *           \f$Q(i)=j\f$ and \f$b_{i,j}=0\f$ otherwise. The the
     *           concatentation of two permutations can be interpreted
     *           as the matrix multiplication
     *           \f[
     *            C=A\cdot B=(c_{i,j})
     *           \f]
     *           where \f$c_{i,j}=1\f$ if \f$R(i)=P(Q(i))=j\f$ and
     *           \f$c_{i,j}=0\f$ otherwise. Therfore, the name of this
     *           method <code>mul</code> suggests that the concatenation
     *           operation is a multiplication.
     *
     * @param R
     *           On output, the concatentation of <i>P</i> and <i>Q</i>.
     *
     * @param P
     *           Outer permutation.
     *
     * @param Q
     *           Inner permutation.
     *
     * @warning
     *           If <i>P</i> and <i>Q</i> operate on a different number
     *           of elements, an error message is printed to
     *           <code>stderr</code> and the program exits with status
     *           'EXIT_FAILURE'.
     *
     * @warning
     *           If not enough memory could be provided, an error
     *           message is printed to <code>stderr</code> and the
     *           program exits with status 'EXIT_FAILURE'.
     */
    void Permutation::mul
    ( Permutation & R ,
      const Permutation & P , const Permutation & Q ) {

        if ( &R == &P || &R == &Q ) {
            Permutation tR;
            mul(tR,P,Q);
            swap(R,tR);
            return;
        }

        int n = P.getDimension();

        if ( n != Q.getDimension() ) {
            cerr << "Permutation::mul: dimensions are different."
                 << endl;
            exit(EXIT_FAILURE);
        }

        // Make 'R' the right dimension and ..
        R.prepareDim(n);

        // .. make it 'P(Q)'.
        for ( int x = 0 ; x < n ; x++ ) {
            int y = P.eval(Q.eval(x));
            R.data[x] = y;
        }
    }

    /**
     * @brief
     *           Computes the inverse of a permutation.
     *
     * @details
     *           The inverse of a permutation
     *           \f$P:\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$ is the
     *           unique \f$R:\{0,...,n-1\}\rightarrow\{0,...,n-1\}\f$
     *           such that \f$R(P(i))=P(R(i))=i\f$.
     *
     * @param R
     *           On output, the inverse of the permutation <i>P</i>.
     *
     * @param P
     *           The permutation of which the inverse is computed.
     *
     * @warning
     *           If not enough memory could be provided, an error
     *           message is printed to <code>stderr</code> and the
     *           program exits with status 'EXIT_FAILURE'.
     */
    void Permutation::inv
    ( Permutation & R , const Permutation & P ) {

        // Ensure that 'R' and 'P' are of different reference.
        if ( &R == &P ) {
            Permutation tP(P);
            inv(R,tP);
            return;
        }

        int n = P.getDimension();

        // Make 'R' the right dimension and ...
        R.prepareDim(n);

        // ... make it the inverse of 'P'
        for ( int x = 0 ; x < n ; x++ ) {
            int y = P.eval(x);
            R.data[y] = x;
        }
    }

    /**
     * @brief
     *           Prints a text representation of a permutation to the
     *           specified output stream.
     *
     * @details
     *           The function prints the following
     *           <pre>
     * [<P(0)> , <P(1)> , ... , <P(n-1)>]
     *           </pre>
     *           where <code><P(i)></code> are replacements for the integers
     *           <code>P.eval(i)</code>. For example, the identity of the
     *           permutation operating on 5 elements is written as
     *           <pre>
     * [0 , 1 , 2 , 3 , 4]
     *           </pre>
     *
     * @param out
     *           The output stream to which a text representation of the
     *           permutation <i>P</i> is written.
     *
     * @param P
     *           The permutation of which a text representation is written
     *           to <code>out</code>.
     *
     * @return
     *           A reference to <code>out</code> after the text representation
     *           has been written.
     */
    ostream & operator<<( ostream & out , const Permutation & P ) {

        out << "[";
        for ( int x = 0 ; x < P.getDimension() ; x++ ) {
            int y = P.eval(x);
            out << y;
            if ( x+1 < P.getDimension() ) {
                out << " , ";
            }
        }
        out << "]";

        return out;
    }
}

