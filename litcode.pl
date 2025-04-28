#!/usr/bin/perl

use strict;
use warnings;

use Cwd qw(getcwd);
use Digest::SHA qw(sha256_hex);
use File::Find;
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir);
use Data::Dumper;

use Getopt::Long;

####################################################################################################

my $HELP_MESSAGE = <<'END_HELP';
Usage: litcode [options] MARKDOWN_FILE_PATH [-- ANY_MORE_PARAMS...]
Options:
  -h, --help     Show this help message
  -v, --verbose  Enable verbose output
  --conv FILE_NAME  Convert the specified file to a different format
  --conv-to-md   Convert the specified file to markdown format
  --ls           List the files
  --cat FILE_NAME  Display the content of the specified file
  --lnum         Display with line numbers

Arguments:
  MARKDOWN_FILE_PATH  Path to the markdown file
  ANY_MORE_PARAMS     Additional parameters (optional)
END_HELP

my $help;
my $verbose;
my $convert_file;
my $convert_to_md;
my $lsfiles;
my $cat_file;
my $line_numbers;

GetOptions(
    'help|h'       => \$help,
    'verbose|v'    => \$verbose,
    'conv=s'       => \$convert_file,
    'conv-to-md'   => \$convert_to_md,
    'ls'           => \$lsfiles,
    'cat=s'        => \$cat_file,
    'lnum'         => \$line_numbers,
) or die "Error in command line arguments. Use --help for usage information.\n";

if ($help) {
    print $HELP_MESSAGE;
    exit 0;
}

# Ensure at least one argument (MARKDOWN_FILE_PATH) is provided
my $markdown_file_path = shift @ARGV;
if (!$markdown_file_path) {
    die "Error: MARKDOWN_FILE_PATH is required. Use --help for usage information.\n";
}

# Additional parameters after '--'
my @additional_params = @ARGV;


sub main {
    if ($lsfiles || $cat_file) {
        main_ls_cat($cat_file);
        return;
    }

    if ($convert_file) {
        main_conv($convert_file);
        return;
    }

    if ($convert_to_md) {
        main_conv_to_md();
        return;
    }

    my $markdown_lines = read_file_markdown_or_source($markdown_file_path);
    my ($rich_lines, $target_dir_file_lines, $key_values, $docker_options) = extract_code_blocks($markdown_file_path, $markdown_lines, undef, undef, undef);
    replace_key_values_in_temp_dir($target_dir_file_lines, $key_values);
    configure_docker_options($docker_options, $target_dir_file_lines);
    build_dockerfile($target_dir_file_lines, $docker_options);
    build_entry_point_sh($target_dir_file_lines);

    my $script_lines = read_script_self();
    my $hash = calc_hash_from_lines([@$markdown_lines, @$script_lines]);
    my $temp_dir = create_temp_dir($hash);

    write_down_source_code_files($temp_dir, $target_dir_file_lines);

    execute_docker($hash, $temp_dir);
}

sub main_ls_cat {
    my ($cat_file) = @_;

    my $markdown_lines = read_file_markdown_or_source($markdown_file_path);
    my ($rich_lines, $target_dir_file_lines, $key_values, $docker_options) = extract_code_blocks($markdown_file_path, $markdown_lines, undef, undef, undef);
    replace_key_values_in_temp_dir($target_dir_file_lines, $key_values);
    configure_docker_options($docker_options, $target_dir_file_lines);
    build_dockerfile($target_dir_file_lines, $docker_options);

    if ($cat_file) {
        if (!$target_dir_file_lines->{$cat_file}) {
            die "Error: File '$cat_file' not found.\n";
        }
        my $target_lines = get_target_dir_file_lines($target_dir_file_lines, $cat_file);
        print join("\n", @$target_lines), "\n";
    } else {
        for my $filename (keys %$target_dir_file_lines) {
            my $file_info = $target_dir_file_lines->{$filename};
            print "$filename\n";
        }
    }
}

sub main_conv {
    my ($conv_file) = @_;

    my $markdown_lines = read_file_markdown_or_source($markdown_file_path);
    my ($rich_lines, $target_dir_file_lines, $key_values, $docker_options) = extract_code_blocks($markdown_file_path, $markdown_lines, undef, undef, undef);
    replace_key_values_in_temp_dir($target_dir_file_lines, $key_values);
    configure_docker_options($docker_options, $target_dir_file_lines);
    build_dockerfile($target_dir_file_lines, $docker_options);

    if (!$target_dir_file_lines->{$conv_file}) {
        die "Error: File '$conv_file' not found.\n";
    }

    my $source_file_path = get_source_file_path($markdown_file_path, $conv_file);
    my $target_lines = convert_to_source_code_file($rich_lines, $target_dir_file_lines, $conv_file);

    print "convert $markdown_file_path to $source_file_path\n";

    if (-e $source_file_path) {
        die "Error: File '$source_file_path' already exists.\n";
    }
    open my $fh, '>', $source_file_path or die "Could not open file '$source_file_path': $!";
    print $fh join("\n", @$target_lines), "\n";
    close $fh;

    unlink $markdown_file_path or die "Could not delete file '$markdown_file_path': $!";
}

sub main_conv_to_md {
    my $markdown_lines = read_file_markdown_or_source($markdown_file_path);

    my $dst_markdown_file_path = get_markdown_file_path($markdown_file_path);

    print "convert $markdown_file_path to $dst_markdown_file_path\n";

    if (-e $dst_markdown_file_path) {
        die "Error: File '$dst_markdown_file_path' already exists.\n";
    }
    open my $fh, '>', $dst_markdown_file_path or die "Could not open file '$dst_markdown_file_path': $!";
    print $fh join("\n", @$markdown_lines), "\n";
    close $fh;

    unlink $markdown_file_path or die "Could not delete file '$markdown_file_path': $!";
}

####################################################################################################

sub create_temp_dir {
    my ($hash) = @_;
    my $temp_dir = tempdir(
        "litcode_${hash}_XXXX",
        DIR => File::Spec->tmpdir(),
        CLEANUP => 1
    );
    return $temp_dir;
}

####################################################################################################

sub read_file_markdown_or_source {
    my ($file_path) = @_;
    my $lines = read_file($file_path);
    my $first_line = $lines->[0];

    if ($first_line =~ /^(\S+):litcode:(\S+) (.+)$/) {
        # Convert to markdown
        return convert_to_markdown($lines);
    } else {
        # Return as is
        return $lines;
    }
}

sub read_script_self {
    my $script_path = $0;
    my $script_lines = read_file($script_path);
    return $script_lines;
}

sub read_file {
    my ($file_path) = @_;
    open my $fh, '<', $file_path or die "Could not open file '$file_path': $!";
    my @lines = <$fh>;
    close $fh;
    my @lines2 = ();
    foreach my $line (@lines) {
        chomp $line;
        push @lines2, $line;
    }
    return \@lines2;
}

sub calc_hash_from_lines {
    my ($lines) = @_;
    my $hash = sha256_hex(join('\n', @$lines) . '\n');
    return $hash;
}

####################################################################################################

sub extract_code_blocks {
    my ($markdown_file_path, $markdown_lines, $target_dir_file_lines, $key_values, $docker_options) = @_;

    if (!$target_dir_file_lines) {
        $target_dir_file_lines = {};
    }
    if (!$key_values) {
        $key_values = {};
    }
    if (!$docker_options) {
        $docker_options = [];
    }

    my ($rich_lines, $blocks) = extract_code_blocks_from_markdown($markdown_lines);

    for (my $line_num = 1; $line_num <= @$rich_lines; $line_num++) {
        my $line_info = $rich_lines->[$line_num - 1];
        my $line = $line_info->{line};

        if ($line_info->{code_block}) {
            my $code_block = $line_info->{code_block};
            my $fence = $code_block->{fence};
            my $lang_label = $code_block->{lang_label};
            my $filename = $code_block->{filename};
            my $block_start = $code_block->{block_start};
            my $block_end = $code_block->{block_end};
            my @lines = @{$code_block->{lines}};

            unless ($target_dir_file_lines->{$filename}) {
                $target_dir_file_lines->{$filename} = [];
            }
            push @{$target_dir_file_lines->{$filename}}, {
                markdown_file_path => $markdown_file_path,
                block_start => $block_start,
                block_end   => $block_end,
                lines       => \@lines,
            };

            next;
        }

        if ($line_info->{is_code_block}) {
            # Skip lines that are part of a code block
            next;
        }

        if ($line =~ /^\s*\$define\s+([_0-9a-zA-Z]+?)\s*=\s*"(.*?)"\s*$/) {
            my $key = $1;
            my $value = $2;
            $key_values->{$key} = $value;
        }

        if ($line =~ /^\s*\$install\s+([_0-9a-zA-Z]+?)\s*$/) {
            my $option = $1;
            push @$docker_options, $option;
        }

        if ($line =~ /^\s*\$include\s+\[\[(.+?)\]\]\s*$/) {
            # Handle: $include [[file_name.md]]

            my $include_file_name = $1;
            my $include_file_path = search_include_file($markdown_file_path, $include_file_name);

            if (!$include_file_path) {
                die "Include file '$include_file_name' not found.\n";
            }
            my $include_lines = read_file($include_file_path);
            extract_code_blocks($include_file_path, $include_lines, $target_dir_file_lines, $key_values, $docker_options);

        }
    }

    return ($rich_lines, $target_dir_file_lines, $key_values, $docker_options);
}

####################################################################################################

sub extract_code_blocks_from_markdown {
    my ($lines) = @_;
    my $blocks = [];
    my $fence = undef;
    my $lang_label = undef;
    my $filename = undef;
    my $block_start = undef;
    my $code_block_lines = undef;
    my $rich_lines = [];

    for (my $line_num = 1; $line_num <= @$lines; $line_num++) {
        my $line = $lines->[$line_num - 1];
        push @$rich_lines, {
            line => $line,
            code_block => undef,
            is_code_block => 0,
            filename => undef,
        };

        if (!$fence) {
            if ($line =~ /^(`{3,})(.*)$/) {
                # Start of code block
                $fence = $1;
                $lang_label = undef;
                $filename = $2;
                $block_start = $line_num;
                $code_block_lines = [];

                # If filename contains a language specifier with space (e.g., "python script.py")
                if ($filename =~ /^(\S+)\s+(.+)$/) {
                    $lang_label = $1;
                    $filename = $2;  # Take everything after the first space as filename
                }

                $filename =~ s/^\s+|\s+$//g;
            }
        } else {
            if ($line =~ /^$fence/) {
                # End of code block
                push @$blocks, {
                    fence       => $fence,
                    lang_label  => $lang_label,
                    filename    => $filename,
                    block_start => $block_start,
                    block_end   => $line_num,
                    lines       => $code_block_lines,
                };
                $rich_lines->[$block_start - 1]->{code_block} = $blocks->[-1];
                $fence = undef;
                next;
            }

            # Inside code block
            push @$code_block_lines, $line;
            $rich_lines->[$line_num - 1]->{is_code_block} = 1;
            $rich_lines->[$line_num - 1]->{filename} = $filename;
        }

    }

    return ($rich_lines, $blocks);
}

####################################################################################################

sub search_include_file {
    my ($markdown_file_path, $include_file_name) = @_;

    if (!$markdown_file_path) {
        return undef;
    }

    # Convert markdown file path to absolute path
    my $abs_markdown_path = File::Spec->rel2abs($markdown_file_path);
    my $markdown_dir = File::Basename::dirname($abs_markdown_path);

    while (1) {
        # Search for include file in the same directory as markdown file
        my $include_path = File::Spec->catfile($markdown_dir, $include_file_name);
        if (-f $include_path) {
            return $include_path;
        }

        # Search for include file in the parent directory
        my $parent_dir = File::Spec->catfile($markdown_dir, '..');
        if ($parent_dir eq $markdown_dir) {
            return undef;
        }
        $markdown_dir = $parent_dir;
    }
}

####################################################################################################

sub convert_to_source_code_file {
    my ($rich_lines, $target_dir_file_lines, $filename) = @_;

    my $target_lines = get_target_dir_file_lines($target_dir_file_lines, $filename);

    my ($lang_label, $uniq_prefix) = get_lang_label_and_unique_prefix($filename, $target_lines);

    my $result_lines = [];

    push @$result_lines, "$uniq_prefix:litcode:$lang_label $filename";

    my $current_code_block = undef;

    for (my $line_num = 1; $line_num <= @$rich_lines; $line_num++) {
        my $line_info = $rich_lines->[$line_num - 1];

        if ($line_info->{filename} && $line_info->{filename} eq $filename) {
            my $result_line = $line_info->{line};
            push @$result_lines, $result_line;
            next;
        }
        if ($current_code_block) {
            $current_code_block = undef;
            next;
        }
        if ($line_info->{code_block}) {
            my $code_block = $line_info->{code_block};
            if ($code_block->{filename} && $code_block->{filename} eq $filename) {
                $current_code_block = $code_block;
                next;
            }
        }
        my $result_line = $uniq_prefix . ' ' . $line_info->{line};
        push @$result_lines, $result_line;
    }

    return $result_lines;
}

####################################################################################################

sub convert_to_markdown {
    my ($lines) = @_;

    if (!@$lines) {
        return [];
    }

    my $first_line = $lines->[0];

    # Interpret $first_line in the format `$uniq_prefix:litcode:$lang_label $file_name`
    if ($first_line !~ /^(\S+):litcode:(\S+) (.+)$/) {
        die "Error: First line of the file does not match the expected format.\n";
    }
    my $uniq_prefix = $1;
    my $lang_label = $2;
    my $filename = $3;

    my $uniq_prefix2 = $uniq_prefix . ' ';

    my $result_lines = [];

    my $current_code_block_lines = undef;
    for (my $line_num = 2; $line_num <= @$lines; $line_num++) {
        my $line = $lines->[$line_num - 1];

        if (index($line, $uniq_prefix2) == 0) {
            if ($current_code_block_lines) {
                my $fence = get_unique_fence($current_code_block_lines);
                push @$result_lines, "$fence$lang_label $filename";
                push @$result_lines, @$current_code_block_lines;
                push @$result_lines, "$fence";
                $current_code_block_lines = undef;
            }
            $line =~ s/^\Q$uniq_prefix2\E//;
            push @$result_lines, $line;
        } else {
            if (!$current_code_block_lines) {
                $current_code_block_lines = [];
            }
            push @$current_code_block_lines, $line;
        }

    }
    if ($current_code_block_lines) {
        my $fence = get_unique_fence($current_code_block_lines);
        push @$result_lines, "$fence$lang_label $filename";
        push @$result_lines, @$current_code_block_lines;
        push @$result_lines, "$fence";
    }
    return $result_lines;
}

####################################################################################################

sub get_target_dir_file_content {
    my ($target_dir_file_lines, $file_name) = @_;
    my $lines = get_target_dir_file_lines($target_dir_file_lines, $file_name);
    my $content = join("\n", @$lines) . "\n";
    return $content;
}

sub get_target_dir_file_lines {
    my ($target_dir_file_lines, $file_name) = @_;
    my $blocks = $target_dir_file_lines->{$file_name};
    my $lines = [];
    foreach my $block (@$blocks) {
        my $block_lines = $block->{lines};
        push @$lines, @$block_lines;
    }
    return $lines;
}

####################################################################################################

sub get_lang_label_and_unique_prefix {
    my ($filename, $lines) = @_;
    my $uniq_prefix;
    my $lang_label;
    if ($filename =~ /\.sh$/) {
        $uniq_prefix = get_unique_prefix($lines, '##');
        $lang_label = 'bash';
    } elsif ($filename =~ /\.py$/) {
        $uniq_prefix = get_unique_prefix($lines, '##');
        $lang_label = 'python';
    } else {
        die "Unsupported file type: $filename\n";
    }
    return ($lang_label, $uniq_prefix);
}

sub get_source_file_path {
    my ($markdown_file_path, $filename) = @_;
    if ($filename =~ /\.sh$/) {
        return $markdown_file_path . '.sh';
    } elsif ($filename =~ /\.py$/) {
        return $markdown_file_path . '.py';
    } else {
        die "Unsupported file type: $filename\n";
    }
}

sub get_markdown_file_path {
    my ($source_file_path) = @_;
    if ($source_file_path =~ /^(.+?)\.md\.sh$/) {
        return "$1.md";
    } elsif ($source_file_path =~ /^(.+?)\.md\.py$/) {
        return "$1.md";
    } else {
        die "Unsupported file type: $source_file_path\n";
    }
}

####################################################################################################

sub get_unique_prefix {
    my ($lines, $minimum_prefix) = @_;
    my @queue = ($minimum_prefix);

    while (@queue) {
        my $prefix = shift @queue;

        # Check if there is a line that starts with $prefix
        my $conflict = 0;
        foreach my $line (@$lines) {
            if (index($line, $prefix) == 0) {
                $conflict = 1;
                last;
            }
        }

        # If there is no conflict, adopt this prefix
        return $prefix unless $conflict;

        # If there is a conflict, try adding # and % to the prefix next
        push @queue, $prefix . '#', $prefix . '%';
    }

    # Normally, this point should not be reached
    die "Could not find a unique prefix";
}

sub get_unique_fence {
    my ($lines) = @_;

    my $max_backticks = 2;

    foreach my $line (@$lines) {
        if ($line =~ /^(\`+)/) {
            my $backticks_count = length($1);
            $max_backticks = $backticks_count if $backticks_count > $max_backticks;
        }
    }

    return '`' x ($max_backticks + 1);
}

####################################################################################################

sub replace_key_values_in_temp_dir {
    my ($target_dir_file_lines, $key_values) = @_;

    my $key_blocks = {};
    for my $filename (keys %$target_dir_file_lines) {
        if (is_real_file($filename)) {
            next;
        }
        my $block_content = get_target_dir_file_content($target_dir_file_lines, $filename);
        $key_blocks->{$filename} = $block_content;
    }


    if ($verbose) {
        for my $key (keys %$key_values) {
            my $value = $key_values->{$key};
            print "\$define $key = \"$value\"\n"
        }
    }
    if (!%$key_values) {
        return;
    }
    foreach my $filename (keys %$target_dir_file_lines) {
        my $file_info = $target_dir_file_lines->{$filename};
        foreach my $block (@$file_info) {
            for (my $i = 0; $i < @{$block->{lines}}; $i++) {
                my $line = $block->{lines}->[$i];
                my $line2 = replace_key_values($line, $key_values, $filename);
                if ($line ne $line2) {
                    $block->{lines}->[$i] = $line2;
                }
            }
        }
    }
}

sub replace_key_values {
    my ($content, $key_values, $filename) = @_;
    foreach my $key (keys %$key_values) {
        my $value = $key_values->{$key};
        $content =~ s/$key/$value/g;
    }
    if ($filename =~ /\.py$/) {
        foreach my $key (keys %$key_blocks) {
            my $value = $key_values->{$key};
            $value = escape_code_block_python_str($value);
            $content =~ s/'$key'/'$value'/g;
            $content =~ s/"$key"/"$value"/g;
        }
    } elsif ($filename =~ /\.pl$/) {
        foreach my $key (keys %$key_blocks) {
            my $value = $key_values->{$key};
            $value = escape_code_block_perl_str($value);
            $content =~ s/"$key"/"$value"/g;
        }
    }
    return $content;
}

sub escape_code_block_python_str {
    my ($code_block) = @_;
    $code_block =~ s/\\/\\\\/g;
    $code_block =~ s/\n/\\n/g;
    $code_block =~ s/\r/\\r/g;
    $code_block =~ s/'/\\'/g;
    $code_block =~ s/"/\\"/g;
    return $code_block;
}

sub escape_code_block_perl_str {
    my ($code_block) = @_;
    $code_block =~ s/\\/\\\\/g;
    $code_block =~ s/\n/\\n/g;
    $code_block =~ s/\r/\\r/g;
    $code_block =~ s/"/\\"/g;
    return $code_block;
}

####################################################################################################

sub configure_docker_options {
    my ($docker_options, $target_dir_file_lines) = @_;

    if (grep { $_ eq 'python' } @$docker_options) {
        if ($target_dir_file_lines->{'requirements.txt'}) {
            push @$docker_options, 'requirements';
        }
    }
}

####################################################################################################

sub build_dockerfile {
    my ($target_dir_file_lines, $docker_options) = @_;

    if ($target_dir_file_lines->{'Dockerfile'}) {
        return;
    }

    my $dockerfile_content = '';

    $dockerfile_content .= <<'EOF';
########################################
FROM debian:12.9

ARG CACHE_BUST=1

RUN apt update
RUN apt install -y libicu-dev
RUN apt install -y lsb-release
RUN apt install -y libssl-dev
RUN apt install -y libffi-dev
RUN apt install -y gcc
RUN apt install -y gnupg
RUN apt install -y curl
RUN apt install -y wget
RUN apt install -y git
RUN apt install -y docker.io

ENV PATH /usr/local/bin:$PATH

########################################
EOF

    if (grep { $_ eq 'python' } @$docker_options) {
        $dockerfile_content .= <<'EOF';
########################################
# Python

# https://github.com/docker-library/python/blob/master/3.13/bookworm/Dockerfile

# runtime dependencies
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		libbluetooth-dev \
		tk-dev \
		uuid-dev \
	; \
	rm -rf /var/lib/apt/lists/*

ENV GPG_KEY 7169605F62C751356D054A26A821E680E5FA6305
ENV PYTHON_VERSION 3.13.2
ENV PYTHON_SHA256 d984bcc57cd67caab26f7def42e523b1c015bbc5dc07836cf4f0b63fa159eb56

RUN set -eux; \
	\
	wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \
	echo "$PYTHON_SHA256 *python.tar.xz" | sha256sum -c -; \
	wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; \
	GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; \
	gpg --batch --verify python.tar.xz.asc python.tar.xz; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" python.tar.xz.asc; \
	mkdir -p /usr/src/python; \
	tar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \
	rm python.tar.xz; \
	\
	cd /usr/src/python; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	./configure \
		--build="$gnuArch" \
		--enable-loadable-sqlite-extensions \
		--enable-optimizations \
		--enable-option-checking=fatal \
		--enable-shared \
		--with-lto \
		--with-ensurepip \
	; \
	nproc="$(nproc)"; \
	EXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; \
	LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; \
		arch="$(dpkg --print-architecture)"; arch="${arch##*-}"; \
# https://docs.python.org/3.12/howto/perf_profiling.html
# https://github.com/docker-library/python/pull/1000#issuecomment-2597021615
		case "$arch" in \
			amd64|arm64) \
				# only add "-mno-omit-leaf" on arches that support it
				# https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/x86-Options.html#index-momit-leaf-frame-pointer-2
				# https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/AArch64-Options.html#index-momit-leaf-frame-pointer
				EXTRA_CFLAGS="${EXTRA_CFLAGS:-} -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer"; \
				;; \
			i386) \
				# don't enable frame-pointers on 32bit x86 due to performance drop.
				;; \
			*) \
				# other arches don't support "-mno-omit-leaf"
				EXTRA_CFLAGS="${EXTRA_CFLAGS:-} -fno-omit-frame-pointer"; \
				;; \
		esac; \
	make -j "$nproc" \
		"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \
		"LDFLAGS=${LDFLAGS:-}" \
	; \
# https://github.com/docker-library/python/issues/784
# prevent accidental usage of a system installed libpython of the same version
	rm python; \
	make -j "$nproc" \
		"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \
		"LDFLAGS=${LDFLAGS:--Wl},-rpath='\$\$ORIGIN/../lib'" \
		python \
	; \
	make install; \
	\
# enable GDB to load debugging data: https://github.com/docker-library/python/pull/701
	bin="$(readlink -ve /usr/local/bin/python3)"; \
	dir="$(dirname "$bin")"; \
	mkdir -p "/usr/share/gdb/auto-load/$dir"; \
	cp -vL Tools/gdb/libpython.py "/usr/share/gdb/auto-load/$bin-gdb.py"; \
	\
	cd /; \
	rm -rf /usr/src/python; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \) \) \
		\) -exec rm -rf '{}' + \
	; \
	\
	ldconfig; \
	\
	export PYTHONDONTWRITEBYTECODE=1; \
	python3 --version; \
	pip3 --version

# make some useful symlinks that are expected to exist ("/usr/local/bin/python" and friends)
RUN set -eux; \
	for src in idle3 pip3 pydoc3 python3 python3-config; do \
		dst="$(echo "$src" | tr -d 3)"; \
		[ -s "/usr/local/bin/$src" ]; \
		[ ! -e "/usr/local/bin/$dst" ]; \
		ln -svT "$src" "/usr/local/bin/$dst"; \
	done

# Python
########################################
EOF
    }

    if (grep { $_ eq 'az' } @$docker_options) {
        $dockerfile_content .= <<'EOF';
########################################
# Azure CLI

RUN curl -sL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
RUN echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/azure-cli.list
RUN apt update
RUN apt install -y azure-cli

RUN curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
RUN mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
RUN echo "deb [arch=amd64] https://packages.microsoft.com/debian/$(lsb_release -rs 2>/dev/null | cut -d'.' -f 1)/prod $(lsb_release -cs 2>/dev/null) main" > /etc/apt/sources.list.d/dotnetdev.list
RUN apt update
RUN apt install -y azure-functions-core-tools-4

# Azure CLI
########################################
EOF
    }

    $dockerfile_content .= <<'EOF';
########################################
WORKDIR /app
########################################
EOF

    if (grep { $_ eq 'requirements' } @$docker_options) {
        $dockerfile_content .= <<'EOF';
########################################
COPY requirements.txt ./
RUN pip install -r requirements.txt
########################################
EOF
    }

    $dockerfile_content .= <<'EOF';
########################################
COPY . .

COPY entry_point.sh ./

ENTRYPOINT ["bash", "./entry_point.sh"]

########################################
EOF

    $target_dir_file_lines->{'Dockerfile'} = [{
        markdown_file_path => undef,
        block_start => undef,
        block_end   => undef,
        lines => content_to_lines($dockerfile_content),
    }];
}

sub build_entry_point_sh {
    my ($target_dir_file_lines) = @_;

    if ($target_dir_file_lines->{'entry_point.sh'}) {
        return;
    }

    my $entry_point_sh_content = <<'EOF';
########################################
set -eu
set -o pipefail

# root ならエラー終了
if [ "$(id -u)" -eq 0 ]; then
  echo "Error: Do not run as root!"
  exit 1
fi

pwd="$1"
shift

input_file="$1"
shift

cd "$pwd"

if [ -n "$input_file" ]; then
    exec 0< "$input_file"
fi

"$@"
########################################
EOF

    $target_dir_file_lines->{'entry_point.sh'} = [{
        markdown_file_path => undef,
        block_start => undef,
        block_end   => undef,
        lines => content_to_lines($entry_point_sh_content),
    }];
}

####################################################################################################

sub write_down_source_code_files {
    my ($temp_dir, $target_dir_file_lines) = @_;

    if (!$target_dir_file_lines) {
        return;
    }

    for my $filename (keys %$target_dir_file_lines) {
        unless (is_real_file($filename)) {
            next;
        }
        my $file_info = $target_dir_file_lines->{$filename};
        my $file_path = File::Spec->catfile($temp_dir, $filename);
        make_path(File::Basename::dirname($file_path));
        open my $fh, '>', $file_path or die "Could not open file '$file_path': $!";
        foreach my $block (@$file_info) {
            print $fh join("\n", @{$block->{lines}}), "\n";
        }
        close $fh;
    }
}

sub is_real_file {
    my ($filename) = @_;
    if ($filename =~ /^__([_0-9a-zA-Z]+?)__$/) {
        return 0;
    } else {
        return 1;
    }
}

####################################################################################################

sub content_to_lines {
    my ($content) = @_;
    my @lines = split /\n/, $content;
    pop @lines if @lines && $lines[-1] eq '';
    return \@lines;
}

####################################################################################################

sub execute_docker {
    my ($hash, $temp_dir) = @_;

    # Execute docker build in temp directory
    # Check if image already exists
    my $check_cmd = "docker image inspect litcode-${hash} >/dev/null 2>&1";
    if (system($check_cmd) != 0) {
        # Image doesn't exist, build it
        my $build_cmd = "cd $temp_dir && docker build . -t litcode-${hash}";
        system($build_cmd) == 0 or die "Docker build failed: $?";
    }

    my $pwd = getcwd();

    # Initialize array to store volume paths
    my @volumes = (
        $temp_dir,  # Mount temp directory containing extracted files
        $pwd        # Mount current working directory
    );

    my $temp_file = "";
    my $io_opt = "";
    if (-t STDOUT && -t STDIN) {
        $io_opt = "-it";
    } elsif (-t STDOUT) {
        $temp_file = tempfile();
        $io_opt = "-t";
    } else {
        $io_opt = "-i";
    }

    if ($temp_file ne "") {
        push @volumes, $temp_file;
        open my $fh, '>', $temp_file or die "Could not open $temp_file: $!";
        while (my $line = <STDIN>) {
            print $fh $line;
        }
        close $fh;
    }

    my $uid = `id -u`;
    chomp $uid;
    my $gid = `id -g`;
    chomp $gid;
    my $user_opt = "--user $uid:$gid";

    my $docker_outside_of_docker = "-v /var/run/docker.sock:/var/run/docker.sock";

    my $volumes_opt = join(" ", map { "-v $_:$_" } @volumes);
    $volumes_opt .= " -v $pwd/.home:$ENV{HOME}";

    my $env_opt = "";
    $env_opt .= " -e HOME=\"$ENV{HOME}\"";
    $env_opt .= " -e TZ=\"$ENV{TZ}\"";

    my $run_cmd = "docker run $io_opt $user_opt $volumes_opt $docker_outside_of_docker $env_opt litcode-${hash} $pwd \"$temp_file\" ";

    my $additional_params_opt = join(" ", map { quotemeta($_) } @additional_params);

    my $main_bash_script = File::Spec->catfile($temp_dir, 'main.sh');
    my $main_python_script = File::Spec->catfile($temp_dir, 'main.py');

    if (-f $main_bash_script) {
        $run_cmd .= "bash /app/main.sh " . $additional_params_opt;
    } elsif (-f $main_python_script) {
        $run_cmd .= "python /app/main.py " . $additional_params_opt;
    } else {
        die "No executable file found in markdown file\n";
    }

    if ($verbose) {
        print "$run_cmd\n";
    }
    # Execute docker run in temp directory
    system($run_cmd);
    exit $?;
}

####################################################################################################

main();
